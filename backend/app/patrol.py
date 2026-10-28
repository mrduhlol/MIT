"""Single-process patrol scheduler. Only analyzes existing simulated telemetry."""
from datetime import datetime, timezone
import threading


class PatrolScheduler:
    def __init__(self, store):
        self.store = store
        self.stop_event = threading.Event()
        self.wake_event = threading.Event()
        self.thread = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name='soc-synthetic-patrol', daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake_event.set()
        if self.thread:
            self.thread.join()

    def wake(self):
        self.wake_event.set()

    def _run(self):
        while not self.stop_event.is_set():
            delay = 60.0
            try:
                settings = self.store.agent_settings()
                if settings['enabled'] and settings['next_run_at']:
                    due = datetime.fromisoformat(settings['next_run_at'])
                    delay = max(0.0, (due - datetime.now(timezone.utc)).total_seconds())
                    if delay <= 0:
                        try:
                            self.store.patrol('scheduled')
                        except RuntimeError:
                            # A manual run owns the non-overlapping patrol lock.
                            pass
                        delay = 1.0
            except Exception:
                # Keep scheduler alive after transient SQLite contention. Patrol
                # failures are durably recorded by Store.patrol itself.
                delay = 5.0
            self.wake_event.wait(min(delay, 60.0))
            self.wake_event.clear()
