"""PAN-OS xpath helpers: safe construction and validation (stdlib only)."""

from __future__ import annotations

import re
from typing import Tuple, Union


class XpathError(ValueError):
    """Raised for an xpath or entry name that could escape its intended node."""


_XPATH_OK = re.compile(r"^/config(/[A-Za-z0-9_\-]+(\[@name='[^'\"<>&]+'\])?)*/?$")
_UNSAFE_NAME = re.compile(r"['\"<>&]")

Part = Union[str, Tuple[str, str]]


def check_xpath(xpath: str) -> str:
    """Reject xpaths with quotes, wildcards, ``//``, ``..`` or predicates other than ``@name``."""
    if not _XPATH_OK.match(xpath or ""):
        raise XpathError(f"refusing unsafe or malformed xpath: {xpath!r}")
    return xpath


def safe_name(name: str) -> str:
    if not name or _UNSAFE_NAME.search(name):
        raise XpathError(f"entry name is empty or contains unsafe characters: {name!r}")
    return name


def entry_xpath(*parts: Part) -> str:
    """Build an xpath from segments. A ``(tag, name)`` tuple becomes ``tag[@name='name']``.

    >>> entry_xpath("devices", ("entry", "localhost.localdomain"), "network")
    "/config/devices/entry[@name='localhost.localdomain']/network"
    """
    out = ["/config"]
    for p in parts:
        if isinstance(p, tuple):
            tag, name = p
            out.append(f"{tag}[@name='{safe_name(name)}']")
        else:
            out.append(p)
    return check_xpath("/".join(out))


def child(base: str, *parts: Part) -> str:
    """Append segments to an existing (already validated) xpath."""
    segs = []
    for p in parts:
        segs.append(f"{p[0]}[@name='{safe_name(p[1])}']" if isinstance(p, tuple) else p)
    return check_xpath(base.rstrip("/") + "/" + "/".join(segs))


#: Xpath roots for a firewall's local config.
FW_DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
FW_NETWORK = FW_DEVICE + "/network"


def fw_vsys(vsys: str = "vsys1") -> str:
    return child(FW_DEVICE, "vsys", ("entry", vsys))


FW_VSYS1 = fw_vsys("vsys1")


def template_root(template: str) -> str:
    """Return the xpath root of a Panorama template's device config (``.../network`` lives under it)."""
    return entry_xpath("devices", ("entry", "localhost.localdomain"), "template", ("entry", template),
                       "config", "devices", ("entry", "localhost.localdomain"))
