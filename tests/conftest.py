import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def odoo_client_module():
    module = importlib.import_module("odoo_mcp.odoo_client")
    return importlib.reload(module)


@pytest.fixture(autouse=True)
def _reset_nesa_per_user_runtime_state():
    """Keep parsed transport and request credentials isolated per test."""
    module = importlib.import_module("odoo_mcp._nesa_per_user_auth")
    module.reset_for_tests()
    yield
    module.reset_for_tests()
