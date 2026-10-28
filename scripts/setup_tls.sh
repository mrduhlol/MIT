#!/usr/bin/env bash
# Local development CA only. Never installs trust globally or replaces existing keys.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
tls_dir=.local-tls
if [[ -L "$tls_dir" ]]; then echo 'Refusing symlink TLS directory.' >&2; exit 1; fi
mkdir -p -m 700 "$tls_dir"
if [[ $(stat -c '%a' "$tls_dir") != 700 || ! -O "$tls_dir" ]]; then
  echo 'TLS directory must be owned by this user with mode 0700.' >&2; exit 1
fi
for item in ca.key ca.crt server.key server.crt; do
  if [[ -L "$tls_dir/$item" ]]; then echo 'Refusing symlink TLS file.' >&2; exit 1; fi
done
if [[ -e "$tls_dir/ca.key" || -e "$tls_dir/ca.crt" || -e "$tls_dir/server.key" || -e "$tls_dir/server.crt" ]]; then
  for item in ca.key ca.crt server.key server.crt; do
    if [[ ! -f "$tls_dir/$item" || ! -O "$tls_dir/$item" || $(stat -c '%a' "$tls_dir/$item") != 600 ]]; then
      echo 'Existing TLS material is incomplete or has unsafe permissions; refusing replacement.' >&2; exit 1
    fi
  done
  openssl verify -CAfile "$tls_dir/ca.crt" -verify_hostname localhost "$tls_dir/server.crt"
  openssl x509 -in "$tls_dir/server.crt" -checkend 86400 -noout
  if [[ $(openssl x509 -in "$tls_dir/server.crt" -pubkey -noout | openssl sha256) != $(openssl pkey -in "$tls_dir/server.key" -pubout 2>/dev/null | openssl sha256) ]]; then
    echo 'Existing server certificate and key do not match; refusing replacement.' >&2; exit 1
  fi
  echo 'Reusing existing verified local development TLS material.'
  exit 0
fi
stage=$(mktemp -d "$tls_dir/.stage.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$stage/ca.key" -out "$stage/ca.crt" -sha256 -days 365 -subj '/CN=AI Defense Local Development CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$stage/server.key" -out "$stage/server.csr" -subj '/CN=localhost' >/dev/null 2>&1
cat > "$stage/extensions.cnf" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EXT
openssl x509 -req -in "$stage/server.csr" -CA "$stage/ca.crt" -CAkey "$stage/ca.key" -CAcreateserial -out "$stage/server.crt" -days 30 -sha256 -extfile "$stage/extensions.cnf" >/dev/null 2>&1
for item in ca.key ca.crt server.key server.crt; do
  chmod 600 "$stage/$item"
  mv -n -- "$stage/$item" "$tls_dir/$item"
done
openssl verify -CAfile "$tls_dir/ca.crt" -verify_hostname localhost "$tls_dir/server.crt"
echo 'Local TLS ready. Agent trust file: .local-tls/ca.crt (never copy ca.key).'
