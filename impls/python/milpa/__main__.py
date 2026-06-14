"""Entry point — delegates to milpa.cli.main()."""

import sys

from milpa.cli import main

if __name__ == "__main__":
    sys.exit(main())
