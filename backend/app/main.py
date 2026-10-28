"""Local-only SOC API. Run with uvicorn app.main:app from backend/."""
from pathlib import Path
import os
import secrets
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, StrictBool
from .store import Store


class ReplayRequest(BaseModel):
    mode: Literal['step', 'all'] = 'step'


class DecisionRequest(BaseModel):
    decision: Literal['approve', 'reject']
    confirmed: StrictBool = False
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


def create_app(db_path=None):
    app = FastAPI(title='AI vs AI — Autonomous Cyber Defense', version='1.0.0', description='Synthetic telemetry and isolated simulated response only.')
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['localhost', '127.0.0.1', '[::1]', 'testserver'])
    app.state.store = Store(db_path or os.environ.get('SOC_DB_PATH', str(Path(__file__).resolve().parents[2] / 'soc.sqlite')))
    app.state.token = secrets.token_urlsafe(32)

    def authorize(request: Request, x_soc_token: str | None = Header(default=None)):
        if not x_soc_token or not secrets.compare_digest(x_soc_token, app.state.token):
            raise HTTPException(403, 'A valid local SOC session token is required.')
        origin = request.headers.get('origin')
        if origin:
            from urllib.parse import urlsplit
            parsed = urlsplit(origin)
            if parsed.hostname not in ('localhost', '127.0.0.1', '[::1]', '::1'):
                raise HTTPException(403, 'Cross-origin mutations are not allowed.')

    @app.get('/api/health')
    def health():
        return {'status': 'ok', 'mode': 'isolated-local-simulation'}

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

    dist = Path(__file__).resolve().parents[2] / 'frontend' / 'dist'
    if dist.is_dir():
        app.mount('/', StaticFiles(directory=dist, html=True), name='dashboard')
    return app


app = create_app()
