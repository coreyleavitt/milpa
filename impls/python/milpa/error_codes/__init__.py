"""Per-category error-code modules. Importing any of these populates
the global ERROR_CATALOG in milpa.error_catalog."""

from . import manifest_codes   # noqa: F401 — side-effect import populates catalog
from . import lockfile_codes   # noqa: F401
from . import resolver_codes   # noqa: F401
from . import solver_codes     # noqa: F401
from . import fetch_codes      # noqa: F401
from . import cas_codes        # noqa: F401
from . import identity_codes   # noqa: F401
from . import nimble_codes     # noqa: F401
from . import frozen_codes     # noqa: F401
from . import workspace_codes  # noqa: F401
from . import extract_codes    # noqa: F401
from . import tianguis_codes   # noqa: F401
