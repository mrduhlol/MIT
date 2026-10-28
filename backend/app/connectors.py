"""Read-only source connectors. Credentials never travel outside validated HTTPS origins."""
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
import http.client
import ipaddress
import json
import os
import socket
import ssl
import threading
import time
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from .servers import Details, StrictModel, TelemetryEvent, timestamp

Category = Literal['authentication', 'suspicious_sessions', 'account_changes', 'application_security']
CATEGORIES = ['authentication', 'suspicious_sessions', 'account_changes', 'application_security']


class ConnectorError(Exception):
    """Only fixed, credential-free messages may be shown to an operator."""


def valid_url(value):
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or any(ord(c) < 33 or ord(c) > 126 for c in value)
                or '\\' in value or '%' in parsed.netloc or port == 0):
            raise ValueError()
        parsed.hostname.encode('ascii')
    except (ValueError, UnicodeError):
        raise ValueError('Use an HTTPS URL without credentials, query parameters or fragments.') from None
    return value.rstrip('/') if not parsed.path else value


def origin(value):
    parsed = urlsplit(value)
    return (parsed.hostname.lower(), parsed.port or 443)


class WebsiteConfig(StrictModel):
    name: str = Field(min_length=1, max_length=80)
    base_url: str = Field(max_length=2048)
    events_url: str = Field(max_length=2048)
    api_key: str = Field(min_length=8, max_length=2048, repr=False)
    categories: list[Category] = Field(min_length=1, max_length=4)

    @field_validator('name')
    @classmethod
    def name_valid(cls, value):
        if not value.strip() or any(ord(c) < 32 for c in value):
            raise ValueError('A visible source name is required.')
        return value.strip()

    @field_validator('base_url', 'events_url')
    @classmethod
    def url_valid(cls, value):
        return valid_url(value)

    @field_validator('api_key')
    @classmethod
    def key_valid(cls, value):
        if any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError('API keys must contain printable ASCII without whitespace.')
        return value

    @model_validator(mode='after')
    def same_origin(self):
        if origin(self.base_url) != origin(self.events_url):
            raise ValueError('The API endpoint must share the website HTTPS origin.')
        if len(set(self.categories)) != len(self.categories):
            raise ValueError('Duplicate event categories are not allowed.')
        return self


class PermissionsRequest(StrictModel):
    categories: list[Category] = Field(min_length=1, max_length=4)

    @field_validator('categories')
    @classmethod
    def unique(cls, value):
        if len(set(value)) != len(value):
            raise ValueError('Duplicate categories are not allowed.')
        return value


class Permissions(StrictModel):
    available: list[Category] = Field(max_length=4)
    granted: list[Category] = Field(max_length=4)

    @model_validator(mode='after')
    def coherent(self):
        if (len(set(self.available)) != len(self.available) or len(set(self.granted)) != len(self.granted)
                or not set(self.granted).issubset(self.available)):
            raise ValueError('Invalid permissions.')
        return self


class WebsiteEvent(StrictModel):
    id: str = Field(min_length=1, max_length=80, pattern=r'^[A-Za-z0-9_.:-]+$')
    timestamp: str
    category: Category
    identity: str = Field(min_length=1, max_length=160)
    ip: str = Field(min_length=1, max_length=45)
    details: Details

    @model_validator(mode='after')
    def valid_event(self):
        normalized = TelemetryEvent(id=self.id, timestamp=self.timestamp, source='auth', identity=self.identity, ip=self.ip, details=self.details)
        self.timestamp, self.ip = normalized.timestamp, normalized.ip
        return self


class WebsiteResponse(StrictModel):
    schema_version: Literal[1]
    telemetry_mode: Literal['real', 'simulated']
    permissions: Permissions
    events: list[WebsiteEvent] = Field(max_length=100)

    @model_validator(mode='after')
    def permitted_events(self):
        if any(event.category not in self.permissions.granted for event in self.events):
            raise ValueError('The API returned an event outside its granted permissions.')
        if len({event.id for event in self.events}) != len(self.events):
            raise ValueError('Duplicate event identifiers in response.')
        return self


class Connector(Protocol):
    def fetch(self, config: dict, api_key: str) -> WebsiteResponse: ...


_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='connector-dns')
_dns_slots = threading.BoundedSemaphore(4)


def resolve(host, port):
    if not _dns_slots.acquire(blocking=False):
        raise ConnectorError('DNS resolver is busy. Retry shortly.')
    def lookup():
        try:
            return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        finally:
            _dns_slots.release()
    future = _dns_pool.submit(lookup)
    try:
        answers = future.result(timeout=3)
    except (FutureTimeout, OSError):
        raise ConnectorError('The API hostname could not be resolved within the connection timeout.') from None
    addresses = sorted({entry[4][0] for entry in answers})
    if not addresses:
        raise ConnectorError('The API hostname has no usable addresses.')
    return addresses


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, context):
        super().__init__(host, port, timeout=5, context=context)
        self.address = address

    def connect(self):
        # No second DNS lookup, proxies, CONNECT tunnel, or redirect support.
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class WebsiteConnector:
    def fetch(self, config, api_key):
        try:
            valid_url(config['events_url'])
            valid_url(config['base_url'])
            if origin(config['base_url']) != origin(config['events_url']):
                raise ValueError()
            target = urlsplit(config['events_url'])
            port = target.port or 443
            allowed = set()
            for entry in os.environ.get('SOC_CONNECTOR_ALLOWED_ORIGINS', '').split(','):
                if entry.strip():
                    valid_url(entry.strip())
                    item = urlsplit(entry.strip())
                    if item.path not in ('', '/'):
                        raise ValueError()
                    allowed.add(origin(entry.strip()))
            private_allowed = origin(config['events_url']) in allowed
            addresses = resolve(target.hostname, port)
            if not private_allowed and (port != 443 or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).is_multicast or ipaddress.ip_address(ip).is_reserved for ip in addresses)):
                raise ConnectorError('Private, loopback and nonstandard-port endpoints require an explicit operator origin allowlist.')
            context = ssl.create_default_context(cafile=os.environ.get('SOC_CONNECTOR_CA_FILE') or None)
        except ConnectorError:
            raise
        except (ValueError, OSError):
            raise ConnectorError('The connector endpoint or TLS trust configuration is invalid.') from None
        conn = PinnedHTTPSConnection(target.hostname, port, addresses[0], context)
        try:
            conn.request('GET', target.path or '/', headers={'Authorization': 'Bearer ' + api_key, 'Accept': 'application/json', 'User-Agent': 'AI-SOC-ReadOnlyConnector/1'})
            response = conn.getresponse()
            if response.status in (401, 403):
                raise ConnectorError('The API rejected the credential or its permissions.')
            if response.status != 200:
                raise ConnectorError('The API did not return HTTP 200. Redirects are not followed.')
            if response.getheader('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
                raise ConnectorError('The API must return the documented JSON security-events contract.')
            length = response.getheader('Content-Length')
            if length and (not length.isdigit() or int(length) > 1024 * 1024):
                raise ConnectorError('The API response exceeds the 1 MiB limit.')
            deadline, chunks, size = time.monotonic() + 10, [], 0
            while True:
                if time.monotonic() > deadline:
                    raise ConnectorError('The API response exceeded the read deadline.')
                chunk = response.read1(min(65536, 1024 * 1024 + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 1024 * 1024:
                    raise ConnectorError('The API response exceeds the 1 MiB limit.')
            try:
                result = WebsiteResponse.model_validate_json(b''.join(chunks))
            except ValueError:
                raise ConnectorError('The API response does not match the documented events and permissions schema.') from None
            return result
        except ConnectorError:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise ConnectorError('The HTTPS API connection failed. Check availability and the trusted certificate.') from None
        finally:
            conn.close()
