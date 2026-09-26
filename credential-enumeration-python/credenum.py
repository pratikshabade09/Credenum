#!/usr/bin/env python3
"""
credenum  --  standalone launcher.

Lets you run the tool as `./credenum.py` (or `python3 credenum.py`) from this
directory without installing anything, in addition to `python3 -m credenum`.
"""

import sys

from credenum.cli import main

if __name__ == "__main__":
    sys.exit(main())
