#!/usr/bin/env python3
"""Entry point: ``python3 fw_troubleshoot.py <diagnose|demo> ...``. All logic lives in :mod:`troubleshoot.cli`."""

import sys

from troubleshoot.cli import main

if __name__ == "__main__":
    sys.exit(main())
