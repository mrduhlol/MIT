"""Keep the module-level ASGI bootstrap away from the operator's live database."""
import os
from pathlib import Path
import tempfile

# main.app is constructed during test collection, before individual fixtures run.
# Each test still uses its explicit tmp_path database; this only isolates that
# otherwise-unused bootstrap app and its generated connector encryption key.
_bootstrap_directory = tempfile.TemporaryDirectory(prefix='soc-pytest-bootstrap-')
os.environ['SOC_DB_PATH'] = str(Path(_bootstrap_directory.name) / 'bootstrap.sqlite')
