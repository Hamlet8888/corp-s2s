#!/usr/bin/env python3
"""Entry point: ``python3 vpn_manager.py <audit|plan|apply|demo> ...``. All logic lives in :mod:`core.cli`."""

import sys

from core.cli import main

if __name__ == "__main__":
    sys.exit(main())
