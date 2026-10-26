"""Backend tests. Importing this package enforces the launcher guard before any test module or conftest
runs (see tests/_launch_guard.py): tests run only through scripts/netra_e2e_pytest.py ``run``."""

from tests._launch_guard import enforce

enforce()
