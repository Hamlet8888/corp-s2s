"""
Safe PAN-OS XML API client for firewalls and Panorama.

Design rules
------------
* **POST only.** Every call sends its parameters in the request body, never
  in the URL, so nothing sensitive ends up in proxy or web-server logs.
* **The API key travels in the ``X-PAN-KEY`` header** (PAN-OS 9.0+). It is
  kept in a private attribute, masked in ``repr()``, and scrubbed from log
  output by :class:`RedactingFilter`.
* **Read-only by default.** ``set`` / ``edit`` / ``delete`` / ``commit`` raise
  :class:`PanosSafetyError` unless the client was created with
  ``allow_writes=True``. With ``dry_run=True``, writes are recorded in
  :attr:`PanosApiClient.journal` (with secrets stripped) instead of being sent.
* **Only reads are retried.** Connection errors on reads get bounded retries
  with backoff. Writes and commits are never retried automatically.
* **TLS verification is on by default.** Pass a CA bundle path if the
  firewalls use a private CA; disabling verification is allowed but logs a
  warning.

Credentials, in order of precedence:

1. ``api_key=...`` passed in directly (e.g. fetched from Secret Server by the caller)
2. ``secret_provider(host)``: a callable returning the key
3. env ``PANOS_API_KEY_<HOST>`` (host upper-cased, non-alphanumerics -> ``_``),
   then ``PANOS_API_KEY``
4. :meth:`PanosApiClient.generate_key` with a username plus a password from
   env ``PANOS_PASSWORD`` or an interactive prompt

Python 3.9+, standard library plus ``requests``.
"""

from __future__ import annotations

import getpass
import logging
import os
import re
import stat
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Union

import requests

from .parser import strip_secrets
from .xpath import FW_DEVICE, FW_NETWORK, FW_VSYS1, XpathError, check_xpath  # noqa: F401 (re-exported)
from .xpath import entry_xpath as _entry_xpath, template_root as _template_root

log = logging.getLogger("corp_s2s.api")

ElementLike = Union[str, ET.Element]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PanosApiError(Exception):
    """Base class for every API failure. Messages never contain credentials."""

    def __init__(self, message: str, code: Optional[str] = None, host: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.host = host


class PanosConnectionError(PanosApiError):
    """The device is unreachable: DNS, TCP, TLS or a proxy failure."""


class PanosTimeoutError(PanosConnectionError):
    """The request or job polling exceeded its time limit."""


class PanosAuthError(PanosApiError):
    """Invalid or expired API key, bad credentials, or insufficient role."""


class PanosLockError(PanosApiError):
    """A config or commit lock held by another admin blocks the operation."""


class PanosResponseError(PanosApiError):
    """Malformed or unexpected XML, or an error status from the API."""


class PanosCommitError(PanosApiError):
    """The commit job finished with FAIL, or reported validation errors."""

    def __init__(self, message: str, job: Optional["JobResult"] = None, **kw):
        super().__init__(message, **kw)
        self.job = job


class PanosSafetyError(PanosApiError):
    """Refused locally: a write on a read-only client, or an unsafe xpath."""


# PAN-OS XML API error codes (subset)
_AUTH_CODES = {"403", "16", "22"}          # forbidden / unauthorized / session timed out
_LOCK_PAT = re.compile(r"\block(ed)?\b|config lock|commit lock", re.I)


# ---------------------------------------------------------------------------
# Log redaction
# ---------------------------------------------------------------------------

class RedactingFilter(logging.Filter):
    """Scrub API keys, passwords and PSKs from any log record this logger emits."""

    _PATTERNS = [
        (re.compile(r"(key=)[^&\s'\"]+", re.I), r"\1<redacted>"),
        (re.compile(r"(password=)[^&\s'\"]+", re.I), r"\1<redacted>"),
        (re.compile(r"(X-PAN-KEY['\"]?\s*[:=]\s*['\"]?)[^'\"\s,}]+", re.I), r"\1<redacted>"),
        (re.compile(r"(<key>)[^<]*(</key>)", re.I), r"\1<redacted>\2"),
        (re.compile(r"(<password>)[^<]*(</password>)", re.I), r"\1<redacted>\2"),
        (re.compile(r"-AQ==[A-Za-z0-9+/=]+"), "<redacted-encrypted>"),
    ]

    def __init__(self, secrets: Optional[List[str]] = None):
        super().__init__()
        self._secrets = [s for s in (secrets or []) if s]

    def add_secret(self, s: Optional[str]) -> None:
        if s and s not in self._secrets:
            self._secrets.append(s)

    def scrub(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "<redacted>")
        for pat, repl in self._PATTERNS:
            text = pat.sub(repl, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        record.msg, record.args = self.scrub(msg), None
        return True


_REDACTOR = RedactingFilter()
log.addFilter(_REDACTOR)


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------

@dataclass
class JobResult:
    job_id: str
    type: Optional[str]
    status: Optional[str]                 # FIN | ACT | PEND | ...
    result: Optional[str]                 # OK | FAIL | PEND
    progress: Optional[str]
    details: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "FIN" and self.result == "OK"


@dataclass
class HAState:
    enabled: bool
    local_state: Optional[str] = None      # active | passive | ...
    peer_state: Optional[str] = None
    running_sync: Optional[str] = None     # synchronized | not synchronized | ...
    running_sync_enabled: Optional[str] = None

    @property
    def in_sync(self) -> bool:
        return not self.enabled or (self.running_sync or "").lower() == "synchronized"


@dataclass
class JournalEntry:
    """A recorded write: sent when ``dry_run`` is off, captured only when it's on."""
    host: str
    action: str
    xpath: Optional[str]
    element: Optional[str]                 # serialized with secrets stripped
    sent: bool


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

def _env_key_name(host: str) -> str:
    return "PANOS_API_KEY_" + re.sub(r"[^A-Za-z0-9]", "_", host).upper()


def _serialize(element: ElementLike) -> str:
    """Return *element* as an XML string, raising if it isn't well-formed."""
    if isinstance(element, ET.Element):
        return ET.tostring(element, encoding="unicode")
    try:
        ET.fromstring(f"<root>{element}</root>")
    except ET.ParseError as exc:
        raise PanosSafetyError(f"element is not well-formed XML: {exc}") from None
    return element


def _redacted_copy(element_xml: str) -> str:
    root = ET.fromstring(f"<root>{element_xml}</root>")
    strip_secrets(root)
    for el in root.iter():
        if el.get("redacted"):
            el.text = "<redacted>"
            del el.attrib["redacted"]
    return "".join(ET.tostring(c, encoding="unicode") for c in root)


class PanosApiClient:
    """XML API client for one firewall or Panorama.

    >>> fw = PanosApiClient("fw01.example.net")            # read-only, key from env
    >>> fw.system_info()["hostname"]                        # doctest: +SKIP
    """

    def __init__(self, host: str, *, api_key: Optional[str] = None,
                 secret_provider: Optional[Callable[[str], str]] = None,
                 username: Optional[str] = None, verify: Union[bool, str] = True,
                 timeout: float = 30.0, retries: int = 2, backoff: float = 1.5,
                 allow_writes: bool = False, dry_run: bool = False,
                 target: Optional[str] = None, vsys: Optional[str] = None,
                 session: Optional[requests.Session] = None, port: int = 443):
        if not re.match(r"^[A-Za-z0-9.\-:\[\]]+$", host):
            raise PanosSafetyError(f"invalid host name: {host!r}")
        self.host = host
        self.base_url = f"https://{host}:{port}/api/" if port != 443 else f"https://{host}/api/"
        self.verify = verify
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self.allow_writes = allow_writes
        self.dry_run = dry_run
        self.target = target              # device serial when proxying through Panorama
        self.vsys = vsys
        self.journal: List[JournalEntry] = []
        self._session = session or requests.Session()
        self._username = username
        self._key: Optional[str] = None
        if verify is False:
            log.warning("%s: TLS certificate verification is DISABLED", host)
        key = api_key or (secret_provider(host) if secret_provider else None) \
            or os.environ.get(_env_key_name(host)) or os.environ.get("PANOS_API_KEY")
        if key:
            self._set_key(key)

    # -- credentials ---------------------------------------------------------
    def __repr__(self) -> str:
        mode = "dry-run" if self.dry_run else ("read-write" if self.allow_writes else "read-only")
        return f"PanosApiClient(host={self.host!r}, key={'set' if self._key else 'unset'}, mode={mode})"

    def _set_key(self, key: str) -> None:
        self._key = key
        _REDACTOR.add_secret(key)

    @property
    def has_key(self) -> bool:
        return self._key is not None

    def generate_key(self, username: Optional[str] = None, password: Optional[str] = None) -> None:
        """Run ``type=keygen`` and keep the key in memory only. It is never returned or logged.

        The password comes from the argument, env ``PANOS_PASSWORD``, or an interactive prompt.
        """
        user = username or self._username or os.environ.get("PANOS_USERNAME")
        if not user:
            raise PanosAuthError("no username for keygen (pass username= or set PANOS_USERNAME)", host=self.host)
        pw = password or os.environ.get("PANOS_PASSWORD") or getpass.getpass(f"Password for {user}@{self.host}: ")
        _REDACTOR.add_secret(pw)
        root = self._request({"type": "keygen", "user": user, "password": pw}, auth=False, read=True)
        key = (root.findtext("result/key") or "").strip()
        if not key:
            raise PanosAuthError("keygen succeeded but returned no key", host=self.host)
        self._set_key(key)
        log.info("%s: API key generated for user %s", self.host, user)

    # -- transport -------------------------------------------------------------
    def _request(self, params: Dict[str, str], *, auth: bool = True, read: bool = True,
                 raw: bool = False, timeout: Optional[float] = None) -> Union[ET.Element, bytes]:
        """POST *params* and return the parsed ``<response>`` (or the raw bytes if *raw*)."""
        if auth and not self._key:
            raise PanosAuthError("no API key: set PANOS_API_KEY[_<HOST>], pass api_key=, or call generate_key()",
                                 host=self.host)
        data = dict(params)
        if self.target and "target" not in data and data.get("type") != "keygen":
            data["target"] = self.target
        if self.vsys and data.get("type") == "config" and "vsys" not in data:
            data["vsys"] = self.vsys
        headers = {"X-PAN-KEY": self._key} if auth else {}
        attempts = 1 + (self.retries if read else 0)
        last_exc: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                log.debug("%s: POST type=%s action=%s (attempt %d/%d)", self.host, data.get("type"),
                          data.get("action", "-"), attempt, attempts)
                resp = self._session.post(self.base_url, data=data, headers=headers, verify=self.verify,
                                          timeout=timeout or self.timeout)
            except requests.exceptions.Timeout as exc:
                last_exc = PanosTimeoutError(f"{self.host}: request timed out after {timeout or self.timeout}s",
                                             host=self.host)
            except requests.exceptions.SSLError as exc:
                raise PanosConnectionError(f"{self.host}: TLS error ({type(exc).__name__}); "
                                           f"check the CA bundle / certificate", host=self.host) from None
            except requests.exceptions.ConnectionError as exc:
                last_exc = PanosConnectionError(f"{self.host}: connection failed ({type(exc).__name__})",
                                                host=self.host)
            else:
                if resp.status_code >= 500 and attempt < attempts:
                    last_exc = PanosConnectionError(f"{self.host}: HTTP {resp.status_code}", host=self.host)
                else:
                    return self._handle(resp, raw=raw)
            if attempt < attempts:
                time.sleep(self.backoff * attempt)
        assert last_exc is not None
        raise last_exc

    def _handle(self, resp: requests.Response, raw: bool) -> Union[ET.Element, bytes]:
        if resp.status_code in (401, 403):
            raise PanosAuthError(f"{self.host}: authentication failed (HTTP {resp.status_code})",
                                 code=str(resp.status_code), host=self.host)
        if resp.status_code >= 400:
            raise PanosResponseError(f"{self.host}: HTTP {resp.status_code}", code=str(resp.status_code),
                                     host=self.host)
        body = resp.content or b""
        if raw and not body.lstrip().startswith(b"<response"):
            return body
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise PanosResponseError(f"{self.host}: invalid XML in response ({exc})", host=self.host) from None
        if root.tag != "response":
            if raw:
                return body
            raise PanosResponseError(f"{self.host}: unexpected root element <{root.tag}>", host=self.host)
        status, code = root.get("status"), root.get("code")
        if status == "error":
            msg = _error_text(root) or "unknown error"
            if code in _AUTH_CODES or re.search(r"invalid credential|api key|unauthori[sz]ed", msg, re.I):
                raise PanosAuthError(f"{self.host}: {msg}", code=code, host=self.host)
            if _LOCK_PAT.search(msg):
                raise PanosLockError(f"{self.host}: {msg}", code=code, host=self.host)
            raise PanosResponseError(f"{self.host}: {msg}", code=code, host=self.host)
        return body if raw else root

    # -- read operations -----------------------------------------------------
    def op(self, cmd: str) -> ET.Element:
        """Run an operational command given as XML, e.g. ``<show><system><info/></system></show>``."""
        _serialize(cmd)
        return self._request({"type": "op", "cmd": cmd})

    def config_get(self, xpath: str) -> ET.Element:
        """Read the candidate config at *xpath* (``action=get``)."""
        return self._request({"type": "config", "action": "get", "xpath": _check_xpath(xpath)})

    def config_show(self, xpath: str) -> ET.Element:
        """Read the running config at *xpath* (``action=show``)."""
        return self._request({"type": "config", "action": "show", "xpath": _check_xpath(xpath)})

    def system_info(self) -> Dict[str, str]:
        root = self.op("<show><system><info/></system></show>")
        sysinfo = root.find("result/system")
        return {c.tag: (c.text or "").strip() for c in (sysinfo if sysinfo is not None else [])}

    def ha_state(self) -> HAState:
        root = self.op("<show><high-availability><state/></high-availability></show>")
        res = root.find("result")
        enabled = (res.findtext("enabled") or "").strip().lower() == "yes" if res is not None else False
        return HAState(
            enabled=enabled,
            local_state=_t(res, "group/local-info/state"),
            peer_state=_t(res, "group/peer-info/state"),
            running_sync=_t(res, "group/running-sync"),
            running_sync_enabled=_t(res, "group/running-sync-enabled"))

    def pending_changes(self) -> bool:
        """Return True if the candidate config has uncommitted changes."""
        root = self.op("<check><pending-changes/></check>")
        return (root.findtext("result") or "").strip().lower() == "yes"

    def locks(self) -> Dict[str, List[str]]:
        """Return the admins holding config and commit locks: ``{'config': [...], 'commit': [...]}``."""
        out: Dict[str, List[str]] = {"config": [], "commit": []}
        for kind, cmd in (("config", "<show><config-locks/></show>"), ("commit", "<show><commit-locks/></show>")):
            root = self.op(cmd)
            for e in root.iter("entry"):
                who = e.get("name") or e.findtext("name") or "?"
                out[kind].append(who.strip())
        return out

    def export_config(self, dest_dir: Union[str, Path] = "backups", label: str = "pre-change",
                      category: str = "configuration") -> Path:
        """Export the running config to ``dest_dir/<host>_<UTC-timestamp>_<label>.xml`` (mode 0600).

        The backup is a full config, including encrypted secrets, so it can be
        restored as-is. It is written with owner-only permissions and must stay
        in the git-ignored ``backups/`` directory.
        """
        body = self._request({"type": "export", "category": category}, raw=True, timeout=max(self.timeout, 120))
        if not isinstance(body, (bytes, bytearray)) or not body.lstrip().startswith(b"<"):
            raise PanosResponseError(f"{self.host}: export did not return XML", host=self.host)
        try:
            ET.fromstring(body)
        except ET.ParseError as exc:
            raise PanosResponseError(f"{self.host}: exported config is not valid XML ({exc})", host=self.host) from None
        d = Path(dest_dir)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, stat.S_IRWXU)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
        path = d / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', self.host)}_{ts}_{safe_label}.xml"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(body)
        log.info("%s: backup written to %s (%d bytes)", self.host, path, len(body))
        return path

    # -- VPN verification (read-only) -------------------------------------------
    def ike_sa(self, gateway: str) -> ET.Element:
        return self.op(f"<show><vpn><ike-sa><gateway>{_xml_text(gateway)}</gateway></ike-sa></vpn></show>")

    def ipsec_sa(self, tunnel: str) -> ET.Element:
        return self.op(f"<show><vpn><ipsec-sa><tunnel>{_xml_text(tunnel)}</tunnel></ipsec-sa></vpn></show>")

    def tunnel_up(self, tunnel: str) -> bool:
        """Return True if at least one IPsec SA exists for *tunnel*."""
        root = self.ipsec_sa(tunnel)
        return any(True for _ in root.iter("entry"))

    def test_vpn_tunnel(self, tunnel: str) -> ET.Element:
        """Trigger IKE/IPsec negotiation for *tunnel* (``test vpn ipsec-sa tunnel X``)."""
        return self.op(f"<test><vpn><ipsec-sa><tunnel>{_xml_text(tunnel)}</tunnel></ipsec-sa></vpn></test>")

    # -- write operations ------------------------------------------------------
    def _guard_write(self, action: str) -> None:
        if not (self.allow_writes or self.dry_run):
            raise PanosSafetyError(f"{self.host}: refusing '{action}' on a read-only client "
                                   f"(create it with allow_writes=True after explicit approval)", host=self.host)

    def _write(self, action: str, xpath: Optional[str], element: Optional[ElementLike],
               extra: Optional[Dict[str, str]] = None) -> Optional[ET.Element]:
        self._guard_write(action)
        xml = _serialize(element) if element is not None else None
        entry = JournalEntry(self.host, action, xpath, _redacted_copy(xml) if xml else None, sent=not self.dry_run)
        self.journal.append(entry)
        if self.dry_run:
            log.info("%s: [dry-run] %s %s", self.host, action, xpath or "")
            return None
        params = {"type": "config", "action": action}
        if xpath:
            params["xpath"] = xpath
        if xml is not None:
            params["element"] = xml
        params.update(extra or {})
        log.info("%s: %s %s", self.host, action, xpath or "")
        return self._request(params, read=False)

    def set(self, xpath: str, element: ElementLike) -> Optional[ET.Element]:
        """Merge *element* under *xpath* (``action=set``). Creates the path if needed."""
        return self._write("set", _check_xpath(xpath), element)

    def edit(self, xpath: str, element: ElementLike) -> Optional[ET.Element]:
        """Replace the node at *xpath* with *element* (``action=edit``)."""
        return self._write("edit", _check_xpath(xpath), element)

    def delete(self, xpath: str) -> Optional[ET.Element]:
        """Delete the node at *xpath* (``action=delete``)."""
        return self._write("delete", _check_xpath(xpath), None)

    def revert_candidate(self) -> None:
        """Discard uncommitted candidate changes (``revert config``, PAN-OS 9.0+)."""
        self._guard_write("revert")
        self.journal.append(JournalEntry(self.host, "revert", None, None, sent=not self.dry_run))
        if self.dry_run:
            return
        log.info("%s: reverting candidate configuration", self.host)
        self._request({"type": "op", "cmd": "<revert><config/></revert>"}, read=False)

    def take_config_lock(self, comment: str = "corp-s2s") -> None:
        self._guard_write("lock")
        if self.dry_run:
            return
        self.op(f"<request><config-lock><add><comment>{_xml_text(comment)}</comment></add></config-lock></request>")

    def release_config_lock(self) -> None:
        if self.dry_run or not self.allow_writes:
            return
        self.op("<request><config-lock><remove/></config-lock></request>")

    @contextmanager
    def config_lock(self, comment: str = "corp-s2s") -> Iterator[None]:
        """Hold the config lock for the duration of the block, and always release it."""
        self.take_config_lock(comment)
        try:
            yield
        finally:
            try:
                self.release_config_lock()
            except PanosApiError as exc:
                log.warning("%s: failed to release config lock: %s", self.host, exc)

    def commit(self, description: str, *, admins: Optional[List[str]] = None, force: bool = False,
               wait: bool = True, timeout: float = 900, poll: float = 5) -> Optional[JobResult]:
        """Commit the candidate config.

        *admins* limits it to a partial commit of those admins' changes.
        Returns the finished :class:`JobResult`, or None in dry-run or when
        there was nothing to commit. Raises :class:`PanosCommitError` if the job fails.
        """
        self._guard_write("commit")
        self.journal.append(JournalEntry(self.host, "commit", None, None, sent=not self.dry_run))
        if self.dry_run:
            log.info("%s: [dry-run] commit %r", self.host, description)
            return None
        partial = ""
        if admins:
            partial = "<partial><admin>" + "".join(f"<member>{_xml_text(a)}</member>" for a in admins) + "</admin></partial>"
        cmd = f"<commit>{'<force/>' if force else ''}{partial}<description>{_xml_text(description)}</description></commit>"
        root = self._request({"type": "commit", "cmd": cmd}, read=False)
        job_id = (root.findtext("result/job") or "").strip()
        if not job_id:
            msg = _error_text(root) or (root.findtext("msg") or "").strip()
            if re.search(r"no changes", msg or "", re.I):
                log.info("%s: commit skipped (no changes)", self.host)
                return None
            raise PanosResponseError(f"{self.host}: commit returned no job id ({msg or 'no message'})", host=self.host)
        log.info("%s: commit job %s enqueued", self.host, job_id)
        if not wait:
            return JobResult(job_id, "Commit", "PEND", "PEND", "0")
        job = self.wait_for_job(job_id, timeout=timeout, poll=poll)
        if not job.ok:
            raise PanosCommitError(f"{self.host}: commit job {job_id} finished {job.result}: "
                                   + "; ".join(job.details[:5]), job=job, host=self.host)
        if job.warnings:
            log.warning("%s: commit job %s finished with warnings: %s", self.host, job_id, "; ".join(job.warnings[:5]))
        return job

    def job_status(self, job_id: str) -> JobResult:
        root = self.op(f"<show><jobs><id>{_xml_text(job_id)}</id></jobs></show>")
        job = root.find("result/job")
        if job is None:
            raise PanosResponseError(f"{self.host}: job {job_id} not found", host=self.host)
        details = [(l.text or "").strip() for l in job.iter("line") if (l.text or "").strip()]
        warnings = [(w.text or "").strip() for w in job.iter("warning") if (w.text or "").strip()]
        warnings += [d for d in details if d.lower().startswith("warning")]
        return JobResult(job_id=job_id, type=_t(job, "type"), status=_t(job, "status"),
                         result=_t(job, "result"), progress=_t(job, "progress"),
                         details=details, warnings=warnings)

    def wait_for_job(self, job_id: str, timeout: float = 900, poll: float = 5) -> JobResult:
        deadline = time.monotonic() + timeout
        while True:
            job = self.job_status(job_id)
            if job.status == "FIN":
                return job
            if time.monotonic() >= deadline:
                raise PanosTimeoutError(f"{self.host}: job {job_id} still {job.status} after {timeout}s "
                                        f"(progress {job.progress}%)", host=self.host)
            time.sleep(poll)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _t(el: Optional[ET.Element], path: str) -> Optional[str]:
    if el is None:
        return None
    v = el.findtext(path)
    return v.strip() if v and v.strip() else None


def _error_text(root: ET.Element) -> str:
    parts: List[str] = []
    for path in ("msg/line", "result/msg/line", "msg", "result/msg", "result/line"):
        for el in root.findall(path):
            txt = "".join(el.itertext()).strip()
            if txt and txt not in parts:
                parts.append(txt)
    return "; ".join(parts)


def _xml_text(value: str) -> str:
    """Escape a value for embedding as element text in an op/commit command."""
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _check_xpath(xpath: str) -> str:
    try:
        return check_xpath(xpath)
    except XpathError as exc:
        raise PanosSafetyError(str(exc)) from None


def entry_xpath(*parts) -> str:
    """Build a validated xpath; see :func:`core.xpath.entry_xpath`."""
    try:
        return _entry_xpath(*parts)
    except XpathError as exc:
        raise PanosSafetyError(str(exc)) from None


def template_root(template: str) -> str:
    """Return the xpath root of a Panorama template's device config."""
    try:
        return _template_root(template)
    except XpathError as exc:
        raise PanosSafetyError(str(exc)) from None
