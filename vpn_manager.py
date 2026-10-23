#!/usr/bin/env python3
"""Entry point: ``python3 vpn_manager.py <audit|plan|apply|demo> ...``. All logic lives in :mod:`s2s_vpn.cli`."""

import sys

from s2s_vpn.cli import main

if __name__ == "__main__":
    sys.exit(main())
