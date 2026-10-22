"""
Live data and verification over the PAN-OS XML API (read-only).

* :func:`pull_config` reads the running config (Panorama-pushed rules included) with secrets stripped.
* :func:`pull_routes` reads the active routing table, so BGP/OSPF routes are part of the lookup.
* :class:`LiveVerifier` asks the firewall itself (``test security-policy-match``,
  ``test nat-policy-match``, ``test routing fib-lookup``) and reports where it disagrees with the
  offline simulation.

Every call here is a read; the client is created without ``allow_writes``.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from core.api import PanosApiClient, PanosApiError, _xml_text
from core.parser import strip_secrets

from .engine import PROTO_NUMBERS, Finding, FlowTrace
from .objects import first_ip
from .policy import PolicyConfig, policy_from_root
from .routing import routes_from_live

_SAFE = re.compile(r"^[A-Za-z0-9_.:/\- ]+$")


def _v(value: str) -> str:
    if not _SAFE.match(value or ""):
        raise ValueError(f"unsafe value for an op command: {value!r}")
    return _xml_text(value)


def pull_config(client: PanosApiClient, vsys: str = "vsys1") -> tuple:
    """Return ``(PolicyConfig, <config> element)`` from the device's running config."""
    root = client.op("<show><config><running/></config></show>")
    cfg = root.find("result/config")
    if cfg is None:
        cfg = root.find(".//config")
    if cfg is None:
        raise PanosApiError(f"{client.host}: running config not found in the response", host=client.host)
    strip_secrets(cfg)
    return policy_from_root(cfg, vsys=vsys, source=f"live: {client.host}"), cfg


def pull_routes(client: PanosApiClient, policy: PolicyConfig) -> Optional[ET.Element]:
    """Replace the config-derived route table with the live one. Returns the raw XML, or None if unavailable."""
    for cmd in ("<show><routing><route/></routing></show>",):
        try:
            root = client.op(cmd)
        except PanosApiError:
            continue
        table = routes_from_live(root, policy.routes.vr_interfaces)
        if table.routes:
            policy.routes = table
            return root
    return None           # Advanced Routing Engine output differs; the config table stays in use


def _rule_names(root: ET.Element) -> List[str]:
    names = []
    for e in root.iter("entry"):
        n = e.get("name") or (e.text or "").split(";")[0].strip()
        if n:
            names.append(n)
    return names


class LiveVerifier:
    """Cross-check simulated traces against the firewall's own policy/route lookups."""

    def __init__(self, client: PanosApiClient, policy: PolicyConfig):
        self.c = client
        self.p = policy

    def verify(self, t: FlowTrace) -> List[Finding]:
        out: List[Finding] = []
        f = t.flow
        src, dst = first_ip(f.src), first_ip(f.dst)
        proto = PROTO_NUMBERS.get(f.proto or "", None)
        if t.from_zone and t.to_zone:
            q = (f"<from>{_v(t.from_zone)}</from><to>{_v(t.to_zone)}</to><source>{_v(src)}</source>"
                 f"<destination>{_v(dst)}</destination>")
            if proto:
                q += f"<protocol>{proto}</protocol>"
            if f.dport is not None:
                q += f"<destination-port>{int(f.dport)}</destination-port>"
            if f.app:
                q += f"<application>{_v(f.app)}</application>"
            try:
                rules = _rule_names(self.c.op(f"<test><security-policy-match>{q}</security-policy-match></test>"))
                live_rule = rules[0] if rules else None
                if live_rule and live_rule != t.security_rule:
                    out.append(Finding("WARNING", "LIVE_POLICY_MISMATCH",
                                       f"The firewall matches {f} to rule '{live_rule}', the export evaluates to "
                                       f"'{t.security_rule}'", ["the export is stale, or the rule depends on "
                                                                "App-ID/User-ID/FQDN data only the firewall has"],
                                       "live"))
                elif live_rule:
                    t.step("live", "ok", f"test security-policy-match -> {live_rule}")
            except (PanosApiError, ValueError) as exc:
                t.step("live", "warn", f"security-policy-match failed: {exc}")
            if proto:
                nq = q.replace(f"<application>{_v(f.app)}</application>", "") if f.app else q
                try:
                    rules = _rule_names(self.c.op(f"<test><nat-policy-match>{nq}</nat-policy-match></test>"))
                    live_nat = rules[0] if rules else None
                    if (live_nat or None) != (t.nat_rule or None):
                        out.append(Finding("WARNING", "LIVE_NAT_MISMATCH",
                                           f"The firewall matches NAT rule '{live_nat or 'none'}', the export "
                                           f"evaluates to '{t.nat_rule or 'none'}'", [str(f)], "live"))
                except (PanosApiError, ValueError) as exc:
                    t.step("live", "warn", f"nat-policy-match failed: {exc}")
        if t.vr and not self.p.routes.live:
            try:
                root = self.c.op(f"<test><routing><fib-lookup><virtual-router>{_v(t.vr)}</virtual-router>"
                                 f"<ip>{_v(dst)}</ip></fib-lookup></routing></test>")
                iface = (root.findtext("result/interface") or "").strip()
                if iface and t.egress_if and iface != t.egress_if:
                    out.append(Finding("WARNING", "LIVE_ROUTE_MISMATCH",
                                       f"Live FIB sends {dst} out {iface}; the config route gives {t.egress_if}",
                                       ["a dynamic route (BGP/OSPF) or path monitoring changed the path"], "live"))
            except (PanosApiError, ValueError):
                pass
        return out
