"""Enables `python3 -m credenum`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
