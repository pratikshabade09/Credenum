"""
credenum  --  Post-access credential exposure detection for Linux systems.

Python port of the Nim project of the same name. Public entry point is
`credenum.cli.main`. See README.md for usage and the EXPLANATION.md for a
walkthrough of the architecture.
"""

from .config import APP_VERSION

__version__ = APP_VERSION
