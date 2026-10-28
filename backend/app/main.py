"""Local-only SOC API. Run with uvicorn app.main:app from backend/."""
from pathlib import Path
from contextlib import asynccontextmanager
import os
import secrets
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, StrictBool
from .store import Store
from .patrol import PatrolScheduler
from .servers import install_routes
from .security import APISecurity


class ReplayRequest(BaseModel):
    mode: Literal['step', 'all'] = 'step'


class AgentSettingsRequest(BaseModel):
    enabled: StrictBool
    interval_seconds: int = Field(ge=30, le=86400, strict=True)


class DecisionRequest(BaseModel):
    decision: Literal['approve', 'reject']
    confirmed: StrictBool = False
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


def create_app(db_path=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.scheduler.start()
        try:
            yield
        finally:
            app.state.scheduler.stop()

    app = FastAPI(lifespan=lifespan, title='AI vs AI — Autonomous Cyber Defense', version='1.0.0', description='Authenticated server telemetry and synthetic fixtures; all containment remains an isolated simulation.')
    allowed_hosts = ['localhost', '127.0.0.1', '[::1]']
    if db_path is not None:
        allowed_hosts.append('testserver')
    for host in os.environ.get('SOC_ALLOWED_HOSTS', '').split(','):
        host = host.strip().lower()
        if host:
            import re
            if '*' in host or not re.fullmatch(r'[a-z0-9.-]+|\[[0-9a-f:]+\]', host):
                raise RuntimeError('SOC_ALLOWED_HOSTS must contain explicit hostnames, without wildcards, schemes or ports.')
            allowed_hosts.append(host)
    app.state.store = Store(db_path or os.environ.get('SOC_DB_PATH', str(Path(__file__).resolve().parents[2] / 'soc.sqlite')))
    app.state.token = secrets.token_urlsafe(32)
    app.state.scheduler = PatrolScheduler(app.state.store)
    app.add_middleware(APISecurity, state=app.state, test_context=db_path is not None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse

    @app.exception_handler(RequestValidationError)
    async def safe_validation_error(request, exc):
        # Never echo request inputs: enrollment requests contain credentials.
        errors = [{'loc': list(error['loc']), 'type': error['type'], 'msg': 'Invalid request field.'} for error in exc.errors()]
        return JSONResponse(status_code=422, content={'detail': errors})

    def authorize(request: Request, x_soc_token: str | None = Header(default=None)):
        if not x_soc_token or not secrets.compare_digest(x_soc_token.encode('latin-1'), app.state.token.encode()):
            raise HTTPException(403, 'A valid local SOC session token is required.')

    @app.get('/api/health')
    def health():
        return {'status': 'ok', 'mode': 'telemetry-monitoring-with-simulated-containment'}

    @app.get('/api/session')
    def session():
        from fastapi.responses import JSONResponse
        return JSONResponse({'token': app.state.token}, headers={'Cache-Control': 'no-store'})

    @app.get('/api/dashboard')
    def dashboard():
        return app.state.store.dashboard()

    @app.post('/api/replay', dependencies=[Depends(authorize)])
    def replay(body: ReplayRequest):
        return app.state.store.replay(body.mode)

    @app.post('/api/reset', dependencies=[Depends(authorize)])
    def reset():
        return app.state.store.reset()

    @app.post('/api/incidents/{incident_id}/investigate', dependencies=[Depends(authorize)])
    def investigate(incident_id: str):
        try:
            return app.state.store.investigate(incident_id)
        except KeyError:
            raise HTTPException(404, 'Incident not found.')

    @app.post('/api/actions/{action_id}/decision', dependencies=[Depends(authorize)])
    def decide(action_id: str, body: DecisionRequest):
        if not body.actor.strip() or not body.reason.strip():
            raise HTTPException(422, 'Actor and reason must contain non-whitespace text.')
        try:
            return app.state.store.decide(action_id, body.decision, body.confirmed, body.actor.strip(), body.reason.strip())
        except KeyError:
            raise HTTPException(404, 'Action not found.')
        except PermissionError as exc:
            raise HTTPException(403, str(exc))
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post('/api/evaluate', dependencies=[Depends(authorize)])
    def evaluate():
        store = app.state.store
        with store.transaction() as db:
            metrics = store.evaluate()
            store.set_meta(db, 'metrics', metrics)
            store.audit(db, 'analyst', 'evaluation_completed', f"Evaluated {metrics['samples']} held-out synthetic events.")
        return metrics

    @app.get('/api/agent')
    def agent():
        return app.state.store.agent()

    @app.post('/api/agent/settings', dependencies=[Depends(authorize)])
    def agent_settings(body: AgentSettingsRequest):
        result = app.state.store.configure_agent(body.enabled, body.interval_seconds)
        app.state.scheduler.wake()
        return result

    @app.post('/api/agent/patrol', dependencies=[Depends(authorize)])
    def agent_patrol():
        try:
            result = app.state.store.patrol('manual')
            app.state.scheduler.wake()
            return result
        except RuntimeError as exc:
            raise HTTPException(409, str(exc))

    @app.get('/api/analytics')
    def analytics(window_minutes: int = 60):
        if window_minutes not in (15, 60, 1440):
            raise HTTPException(422, 'window_minutes must be 15, 60 or 1440.')
        return app.state.store.analytics(window_minutes)

    install_routes(app, authorize)

    dist = Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
    if dist.is_dir():
        app.mount('/', StaticFiles(directory=dist, html=True), name='dashboard')
    return app


app = create_app()
