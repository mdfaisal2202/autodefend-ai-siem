#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoDefend AI-SIEM :: SOAR Backend Engine
=========================================

A self-contained Security Orchestration, Automation and Response (SOAR) pipeline that:

    1. INGESTS   raw logs from Wazuh (JSON alerts file), Syslog (RFC3164/5424), or a built-in
                 attack simulator, using a poll/tail loop.
    2. NORMALIZES every raw record into a single canonical JSON "SecurityEvent" schema.
    3. REASONS   on the normalized event with a locally-hosted LLM via Ollama
                 (http://localhost:11434/api/generate) requesting structured JSON output:
                 risk_score, intent, severity, verdict (plain-English triage).
    4. RESPONDS  by executing containment playbooks when the AI classifies the event as
                 CRITICAL/HIGH: firewall blocklist append, iptables rule generation,
                 process termination (PID kill), and account lockout.
    5. PERSISTS  a tamper-evident audit trail to SQLite (autodefend.db) AND a flat CSV
                 (autodefend_db.csv) so a Streamlit "Security Cockpit" can read a live feed.

Design goals: zero placeholder code, deterministic degradation (never crash when the LLM is
offline), idempotent mitigation, and an append-only audit record of every decision.

Author : AutoDefend Project
License: MIT
Python : 3.10+ (tested on 3.14)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
    try:
        from urllib3.util.retry import Retry
    except Exception:  # pragma: no cover
        Retry = None  # type: ignore
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "[FATAL] The 'requests' library is required. Install it with:\n"
        "        pip install requests\n"
    )
    raise SystemExit(1) from exc


# --------------------------------------------------------------------------------------
# Section 1 :: Configuration
# --------------------------------------------------------------------------------------

def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name, "true" if default else "false").strip().lower()
    return raw in {"1", "true", "yes", "y", "on"}


@dataclass
class Config:
    """Runtime configuration. Every field is overridable via environment variables."""

    # --- Ollama / LLM ---
    ollama_url: str = _env("AUTODEFEND_OLLAMA_URL", "http://localhost:11434/api/generate")
    ollama_model: str = _env("AUTODEFEND_OLLAMA_MODEL", "llama3")
    llm_timeout: int = _env_int("AUTODEFEND_LLM_TIMEOUT", 60)
    llm_max_retries: int = _env_int("AUTODEFEND_LLM_RETRIES", 2)

    # --- Ingestion ---
    # "file"  : tail a JSON-lines / syslog file (real Wazuh output)
    # "simulate": generate realistic synthetic attack traffic (no infra needed)
    ingest_mode: str = _env("AUTODEFEND_INGEST_MODE", "simulate")
    log_file: str = _env("AUTODEFEND_LOG_FILE", "/var/ossec/logs/alerts/alerts.json")
    poll_interval: float = _env_float("AUTODEFEND_POLL_INTERVAL", 2.0)
    simulate_interval: float = _env_float("AUTODEFEND_SIMULATE_INTERVAL", 5.0)

    # --- Enforcement ---
    dry_run: bool = _env_bool("AUTODEFEND_DRY_RUN", True)
    enforce_min_severity: str = _env("AUTODEFEND_ENFORCE_MIN_SEVERITY", "HIGH").upper()
    blocklist_path: str = _env("AUTODEFEND_BLOCKLIST", "firewall_blocklist.txt")
    iptables_rules_path: str = _env("AUTODEFEND_IPTABLES_RULES", "autodefend_iptables.rules")
    allowed_kill_pids: str = _env("AUTODEFEND_ALLOWED_KILL_PIDS", "")
    protected_pids: str = _env("AUTODEFEND_PROTECTED_PIDS", "1")

    # --- Persistence ---
    sqlite_path: str = _env("AUTODEFEND_DB", "autodefend.db")
    csv_path: str = _env("AUTODEFEND_CSV", "autodefend_db.csv")

    # --- Misc ---
    log_level: str = _env("AUTODEFEND_LOG_LEVEL", "INFO").upper()

    def as_public_dict(self) -> Dict[str, Any]:
        """Config snapshot with secrets/paths marked, safe to persist in the audit DB."""
        return {
            "ollama_url": self.ollama_url,
            "ollama_model": self.ollama_model,
            "ingest_mode": self.ingest_mode,
            "log_file": self.log_file,
            "dry_run": self.dry_run,
            "enforce_min_severity": self.enforce_min_severity,
            "blocklist_path": self.blocklist_path,
            "iptables_rules_path": self.iptables_rules_path,
            "sqlite_path": self.sqlite_path,
            "csv_path": self.csv_path,
        }


SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Wazuh rule level -> coarse severity mapping (used as a deterministic fallback signal).
WAZUH_LEVEL_TO_SEVERITY: List[Tuple[int, str]] = [
    (12, "CRITICAL"),
    (9, "HIGH"),
    (6, "MEDIUM"),
    (3, "LOW"),
    (0, "INFO"),
]

MITIGATION_SEVERITIES = {"HIGH", "CRITICAL"}


# --------------------------------------------------------------------------------------
# Section 2 :: Logging
# --------------------------------------------------------------------------------------

class _ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;41m",
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        base = super().format(record)
        if sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, "")
            if color:
                return f"{color}{base}{self.RESET}"
        return base


def configure_logging(level: str) -> logging.Logger:
    logger = logging.getLogger("autodefend")
    logger.setLevel(getattr(logging, level, logging.INFO))
    logger.handlers.clear()

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(
        _ColorFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    logger.addHandler(stream)
    logger.propagate = False
    return logger


LOG = configure_logging("INFO")  # re-configured in main()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------------------
# Section 3 :: Canonical SecurityEvent schema + normalization
# --------------------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """One canonical, normalized security event that flows through the whole pipeline."""

    event_id: str
    ingest_ts: str
    source: str                      # wazuh | syslog | simulator
    host: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    username: Optional[str]
    process: Optional[str]
    pid: Optional[int]
    event_type: str                  # e.g. ssh_bruteforce, web_scan, priv_esc, ...
    wazuh_rule_id: Optional[str]
    wazuh_rule_level: Optional[int]
    signature: str
    raw: Dict[str, Any] = field(default_factory=dict)
    raw_hash: str = ""

    @staticmethod
    def new_id() -> str:
        return f"EVT-{uuid.uuid4().hex[:12].upper()}"


def _first(container: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present, non-empty value among keys (supports nested 'a.b')."""
    for key in keys:
        node: Any = container
        ok = True
        for part in key.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                ok = False
                break
        if ok and node not in (None, ""):
            return node
    return default


def _to_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return None


def _valid_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return None


class LogNormalizer:
    """Turns heterogeneous raw records into canonical SecurityEvent objects."""

    SYSLOG_RE = re.compile(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+(?P<proc>[\w\-\./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
    )
    KV_RE = re.compile(r"(?P<key>[A-Za-z_][\w\.\-]*)=(?P<val>\"[^\"]*\"|\S+)")
    IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # Signature keywords -> normalized event_type classification.
    SIGNATURES: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"brute[ _-]?force|authentication failure|failed password|invalid user", re.I), "ssh_bruteforce"),
        (re.compile(r"sql injection|union select|' or '1'='1|sqli", re.I), "web_sqli_attempt"),
        (re.compile(r"scan|nmap|port sweep|probe", re.I), "network_scan"),
        (re.compile(r"privilege escalat|sudo:.*COMMAND|su:.*authentication|rootkit", re.I), "privilege_escalation"),
        (re.compile(r"malware|trojan|ransom|reverse shell|/dev/tcp/", re.I), "malware_execution"),
        (re.compile(r"web shell|\.php\?cmd=|cmd\.exe|/bin/sh -c", re.I), "webshell_activity"),
        (re.compile(r"directory traversal|\.\./\.\./|%2e%2e%2f", re.I), "path_traversal"),
        (re.compile(r"ddos|syn flood|dos attack|flood", re.I), "dos_flood"),
        (re.compile(r"data exfiltration|large outbound|curl .* \| bash", re.I), "exfiltration_attempt"),
    ]

    def __init__(self) -> None:
        self.log = logging.getLogger("autodefend.normalizer")

    # -- public API --------------------------------------------------------------------
    def normalize(self, source: str, record: Any) -> Optional[SecurityEvent]:
        try:
            if source == "wazuh":
                return self._from_wazuh(record)
            if source == "syslog":
                return self._from_syslog(record)
            return self._from_generic(record)
        except Exception as exc:  # never let a single bad record kill the loop
            self.log.warning("Normalization failed for %s record: %s", source, exc)
            return None

    # -- source-specific parsers -------------------------------------------------------
    def _from_wazuh(self, record: Dict[str, Any]) -> SecurityEvent:
        rule = record.get("rule", {}) if isinstance(record.get("rule"), dict) else {}
        data = record.get("data", {}) if isinstance(record.get("data"), dict) else {}
        agent = record.get("agent", {}) if isinstance(record.get("agent"), dict) else {}
        full_log = str(_first(record, "full_log", "full_log.message", default=""))

        src_ip = _valid_ip(_first(data, "srcip", "src_ip", "src_address")) or _valid_ip(
            self._guess_ip(full_log)
        )
        rule_level = _to_int(_first(rule, "level"))
        rule_id = _first(rule, "id")
        description = str(_first(rule, "description", default=""))
        event_type = self._classify(f"{description} {full_log}")

        return SecurityEvent(
            event_id=SecurityEvent.new_id(),
            ingest_ts=utc_now(),
            source="wazuh",
            host=str(_first(agent, "name", "id", default=_first(record, "host", default="unknown"))),
            src_ip=src_ip,
            dst_ip=_valid_ip(_first(data, "dstip", "dst_ip")),
            src_port=_to_int(_first(data, "srcport", "src_port")),
            dst_port=_to_int(_first(data, "dstport", "dst_port")),
            protocol=_first(data, "protocol"),
            username=_first(data, "dstuser", "srcuser", "username"),
            process=_first(data, "program", "process", "command"),
            pid=_to_int(_first(data, "pid")),
            event_type=event_type,
            wazuh_rule_id=str(rule_id) if rule_id is not None else None,
            wazuh_rule_level=rule_level,
            signature=description or event_type,
            raw=record,
            raw_hash=self._hash(record),
        )

    def _from_syslog(self, line: str) -> SecurityEvent:
        text = line.strip()
        match = self.SYSLOG_RE.match(text)
        host, proc, pid, msg = "unknown", "syslog", None, text
        if match:
            host = match.group("host")
            proc = match.group("proc")
            pid = _to_int(match.group("pid"))
            msg = match.group("msg")

        kv = {k: v.strip('"') for k, v in self.KV_RE.findall(msg)}
        event_type = self._classify(msg)

        return SecurityEvent(
            event_id=SecurityEvent.new_id(),
            ingest_ts=utc_now(),
            source="syslog",
            host=host,
            src_ip=_valid_ip(_first(kv, "src", "src_ip", "from")) or _valid_ip(self._guess_ip(msg)),
            dst_ip=_valid_ip(_first(kv, "dst", "dst_ip")),
            src_port=_to_int(_first(kv, "sport", "src_port")),
            dst_port=_to_int(_first(kv, "dport", "dst_port", "port")),
            protocol=_first(kv, "proto", "protocol"),
            username=_first(kv, "user", "username", "invalid_user"),
            process=proc,
            pid=pid,
            event_type=event_type,
            wazuh_rule_id=None,
            wazuh_rule_level=None,
            signature=msg[:240],
            raw={"line": text, "kv": kv},
            raw_hash=self._hash(text),
        )

    def _from_generic(self, record: Dict[str, Any]) -> SecurityEvent:
        text = json.dumps(record, default=str)
        event_type = self._classify(str(_first(record, "signature", "event_type", "message", default=text)))
        return SecurityEvent(
            event_id=SecurityEvent.new_id(),
            ingest_ts=utc_now(),
            source=str(_first(record, "source", default="generic")),
            host=str(_first(record, "host", default="unknown")),
            src_ip=_valid_ip(_first(record, "src_ip", "srcip")),
            dst_ip=_valid_ip(_first(record, "dst_ip", "dstip")),
            src_port=_to_int(_first(record, "src_port")),
            dst_port=_to_int(_first(record, "dst_port")),
            protocol=_first(record, "protocol"),
            username=_first(record, "username", "user"),
            process=_first(record, "process"),
            pid=_to_int(_first(record, "pid")),
            event_type=event_type,
            wazuh_rule_id=str(_first(record, "rule_id")) if _first(record, "rule_id") else None,
            wazuh_rule_level=_to_int(_first(record, "rule_level")),
            signature=str(_first(record, "signature", default=event_type)),
            raw=record,
            raw_hash=self._hash(record),
        )

    # -- helpers -----------------------------------------------------------------------
    def _classify(self, text: str) -> str:
        for pattern, label in self.SIGNATURES:
            if pattern.search(text or ""):
                return label
        return "anomaly_unclassified"

    @staticmethod
    def _guess_ip(text: str) -> Optional[str]:
        found = LogNormalizer.IP_RE.search(text or "")
        if not found:
            return None
        candidate = found.group(0)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            return None

    @staticmethod
    def _hash(payload: Any) -> str:
        blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


def wazuh_level_to_severity(level: Optional[int]) -> str:
    if level is None:
        return "MEDIUM"
    for threshold, severity in WAZUH_LEVEL_TO_SEVERITY:
        if level >= threshold:
            return severity
    return "INFO"


# --------------------------------------------------------------------------------------
# Section 4 :: Log sources (Wazuh file tailer, Syslog reader, Attack simulator)
# --------------------------------------------------------------------------------------

class LogSource:
    """Base class: yields (source, record) tuples forever."""

    name = "base"

    def stream(self, stop: threading.Event) -> Iterator[Tuple[str, Any]]:
        raise NotImplementedError

    def close(self) -> None:
        return None


class FileTailSource(LogSource):
    """Tails an append-only log file, parsing JSON-lines (Wazuh) or raw syslog lines."""

    name = "file"

    def __init__(self, path: str, poll_interval: float, parser: str = "auto") -> None:
        self.path = Path(path)
        self.poll_interval = poll_interval
        self.parser = parser
        self.log = logging.getLogger("autodefend.source.file")
        self._fh: Optional[Any] = None
        self._ino: Optional[int] = None

    def _open(self) -> bool:
        try:
            self._fh = self.path.open("r", encoding="utf-8", errors="replace")
            self._fh.seek(0, os.SEEK_END)
            self._ino = os.fstat(self._fh.fileno()).st_ino
            self.log.info("Tailing %s (from end-of-file)", self.path)
            return True
        except FileNotFoundError:
            self.log.debug("Waiting for log file %s to appear...", self.path)
            return False
        except PermissionError:
            self.log.error("Permission denied reading %s (try sudo or fix ACLs)", self.path)
            return False

    def stream(self, stop: threading.Event) -> Iterator[Tuple[str, Any]]:
        while not stop.is_set():
            if self._fh is None and not self._open():
                stop.wait(self.poll_interval)
                continue

            line = self._fh.readline()
            if not line:
                if self._rotated():
                    self._fh.close()
                    self._fh = None
                stop.wait(self.poll_interval)
                continue

            line = line.strip()
            if not line:
                continue
            parsed = self._parse_line(line)
            if parsed is not None:
                source, record = parsed
                yield source, record

    def _rotated(self) -> bool:
        try:
            current = os.stat(self.path).st_ino
            return current != self._ino
        except FileNotFoundError:
            return True

    def _parse_line(self, line: str) -> Optional[Tuple[str, Any]]:
        if self.parser in ("auto", "wazuh") and line.startswith("{"):
            try:
                return "wazuh", json.loads(line)
            except json.JSONDecodeError:
                if self.parser == "wazuh":
                    self.log.debug("Malformed JSON line skipped")
                    return None
        if self.parser in ("auto", "syslog"):
            return "syslog", line
        return None

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class AttackSimulator(LogSource):
    """Generates realistic Wazuh-shaped alerts so the pipeline can be demonstrated offline."""

    name = "simulate"

    SCENARIOS: List[Dict[str, Any]] = [
        {
            "rule_id": "5710", "rule_level": 12, "type": "ssh_bruteforce",
            "description": "sshd: brute force attack detected (multiple authentication failures)",
            "user": "root", "dst_port": 22, "protocol": "tcp",
        },
        {
            "rule_id": "5712", "rule_level": 10, "type": "ssh_bruteforce",
            "description": "sshd: repeated failed password for invalid user admin",
            "user": "admin", "dst_port": 22, "protocol": "tcp",
        },
        {
            "rule_id": "31151", "rule_level": 9, "type": "network_scan",
            "description": "Multiple port scan attempts detected from external host (nmap SYN scan)",
            "user": None, "dst_port": 443, "protocol": "tcp",
        },
        {
            "rule_id": "31103", "rule_level": 6, "type": "web_sqli_attempt",
            "description": "SQL injection attempt detected in URL query (union select)",
            "user": None, "dst_port": 80, "protocol": "http",
        },
        {
            "rule_id": "5920", "rule_level": 13, "type": "malware_execution",
            "description": "Possible reverse shell / malware payload executed (/dev/tcp/ detection)",
            "user": "www-data", "dst_port": 4444, "protocol": "tcp",
        },
        {
            "rule_id": "5901", "rule_level": 11, "type": "privilege_escalation",
            "description": "Privilege escalation attempt: unauthorized sudo command executed",
            "user": "svc_backup", "dst_port": None, "protocol": None,
        },
        {
            "rule_id": "31166", "rule_level": 7, "type": "path_traversal",
            "description": "Directory traversal attempt (../../etc/passwd) blocked",
            "user": None, "dst_port": 8080, "protocol": "http",
        },
    ]

    INTERNAL_HOSTS = ["web-prod-01", "db-prod-02", "bastion-01", "k8s-node-07", "jump-host-03"]

    def __init__(self, interval: float) -> None:
        self.interval = interval
        self.log = logging.getLogger("autodefend.source.simulator")
        self._rng = random.Random(1337)

    @staticmethod
    def _random_external_ip(rng: random.Random) -> str:
        if rng.random() < 0.25:  # sometimes reuse a "known attacker" IP
            return rng.choice(["203.0.113.66", "198.51.100.23"])
        return ".".join(str(rng.randint(1, 254)) for _ in range(4))

    def stream(self, stop: threading.Event) -> Iterator[Tuple[str, Any]]:
        self.log.info("Attack simulator active (interval=%.1fs)", self.interval)
        while not stop.is_set():
            scenario = self._rng.choice(self.SCENARIOS)
            src_ip = self._random_external_ip(self._rng)
            host = self._rng.choice(self.INTERNAL_HOSTS)
            pid = self._rng.randint(400, 32000)

            alert = {
                "timestamp": utc_now(),
                "agent": {"id": f"00{self._rng.randint(1, 9)}", "name": host, "ip": "10.0.0.5"},
                "manager": {"name": "autodefend-manager"},
                "rule": {
                    "id": scenario["rule_id"],
                    "level": scenario["rule_level"],
                    "description": scenario["description"],
                    "groups": ["autodefend", scenario["type"]],
                },
                "data": {
                    "srcip": src_ip,
                    "dstip": "10.0.0.5",
                    "srcport": self._rng.randint(32000, 65000),
                    "dstport": scenario["dst_port"],
                    "protocol": scenario["protocol"],
                    "dstuser": scenario["user"],
                    "program": "sshd" if "ssh" in scenario["type"] else "kernel",
                    "pid": pid,
                },
                "location": f"/var/log/{'auth.log' if 'ssh' in scenario['type'] else 'syslog'}",
                "full_log": (
                    f"{utc_now()} {host} {'sshd' if 'ssh' in scenario['type'] else 'kernel'}[{pid}]: "
                    f"{scenario['description']} src={src_ip} dstport={scenario['dst_port']}"
                ),
                "autodefend_simulated": True,
                "scenario_type": scenario["type"],
            }
            self.log.info("Simulated alert: %s from %s", scenario["type"], src_ip)
            yield "wazuh", alert
            stop.wait(self.interval)


class QueueLogSource(LogSource):
    """Bridges an in-memory/alerts queue (e.g. a Syslog UDP listener) into the pipeline."""

    name = "queue"

    def __init__(self, queue: "Queue[Tuple[str, Any]]") -> None:
        self.queue = queue

    def stream(self, stop: threading.Event) -> Iterator[Tuple[str, Any]]:
        while not stop.is_set():
            try:
                yield self.queue.get(timeout=0.5)
            except Empty:
                continue


# --------------------------------------------------------------------------------------
# Section 5 :: LLM triage (Ollama) with deterministic fallback
# --------------------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    risk_score: int
    severity: str
    intent: str
    verdict: str
    recommended_action: str
    mitre_technique: str
    confidence: float
    model_used: str
    raw_response: str
    fallback_used: bool = False
    llm_latency_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SYSTEM_PROMPT = (
    "You are AutoDefend, a senior SOC (Security Operations Center) triage analyst AI. "
    "You receive one normalized security event as JSON and must return ONLY a single JSON object. "
    "Do not include markdown, commentary, or code fences. "
    "Classify the event, compute a risk score, and give a plain-English triage verdict that a "
    "non-technical executive could understand."
)

OUTPUT_CONTRACT = {
    "risk_score": "integer 0-100 (overall risk)",
    "severity": "one of INFO | LOW | MEDIUM | HIGH | CRITICAL",
    "intent": "short attacker intent phrase, e.g. 'credential brute forcing'",
    "verdict": "1-3 sentence plain-English triage explanation",
    "recommended_action": "one of MONITOR | BLOCK_IP | KILL_PROCESS | LOCK_ACCOUNT | BLOCK_IP_AND_KILL",
    "mitre_technique": "nearest MITRE ATT&CK technique id and name, e.g. 'T1110 Brute Force'",
    "confidence": "float 0.0-1.0 confidence in this assessment",
}


class OllamaAnalyst:
    """Thin, resilient client around the Ollama /api/generate endpoint."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("autodefend.llm")
        self.session = self._build_session()
        self._health_checked = False
        self._healthy = False

    def _build_session(self) -> "requests.Session":
        session = requests.Session()
        if Retry is not None:
            retry = Retry(
                total=self.cfg.llm_max_retries,
                backoff_factor=0.8,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["POST"]),
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
        return session

    def _build_prompt(self, event: SecurityEvent) -> str:
        payload = {
            "event_id": event.event_id,
            "source": event.source,
            "host": event.host,
            "event_type": event.event_type,
            "src_ip": event.src_ip,
            "dst_port": event.dst_port,
            "protocol": event.protocol,
            "username": event.username,
            "process": event.process,
            "pid": event.pid,
            "wazuh_rule_id": event.wazuh_rule_id,
            "wazuh_rule_level": event.wazuh_rule_level,
            "signature": event.signature,
        }
        return (
            f"{SYSTEM_PROMPT}\n\n"
            f"OUTPUT JSON SCHEMA:\n{json.dumps(OUTPUT_CONTRACT, indent=2)}\n\n"
            f"SECURITY EVENT:\n{json.dumps(payload, indent=2)}\n\n"
            f"Respond with the JSON object only."
        )

    def _check_health(self) -> bool:
        base = self.cfg.ollama_url.split("/api/")[0]
        try:
            resp = self.session.get(f"{base}/api/tags", timeout=5)
            self._healthy = resp.status_code == 200
            if self._healthy:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                self.log.info("Ollama reachable. Local models: %s", ", ".join(models) or "(none pulled)")
                if models and not any(m.startswith(self.cfg.ollama_model) for m in models):
                    self.log.warning(
                        "Configured model '%s' not found locally. Run: ollama pull %s",
                        self.cfg.ollama_model, self.cfg.ollama_model,
                    )
            else:
                self.log.warning("Ollama health probe returned HTTP %s", resp.status_code)
        except requests.RequestException as exc:
            self._healthy = False
            self.log.warning("Ollama not reachable (%s). Falling back to heuristic triage.", exc)
        self._health_checked = True
        return self._healthy

    def assess(self, event: SecurityEvent) -> RiskAssessment:
        if not self._health_checked or not self._healthy:
            if not self._check_health():
                return self._heuristic_assessment(event, reason="ollama_unavailable")

        started = time.monotonic()
        body = {
            "model": self.cfg.ollama_model,
            "prompt": self._build_prompt(event),
            "stream": False,
            "format": "json",              # force structured JSON output
            "options": {"temperature": 0.1, "num_predict": 384},
        }
        try:
            resp = self.session.post(self.cfg.ollama_url, json=body, timeout=self.cfg.llm_timeout)
            resp.raise_for_status()
            payload = resp.json()
            text = payload.get("response", "")
            latency = int((time.monotonic() - started) * 1000)
            assessment = self._parse_model_json(text, model=payload.get("model", self.cfg.ollama_model))
            assessment.llm_latency_ms = latency
            return assessment
        except requests.RequestException as exc:
            self.log.error("LLM inference failed: %s", exc)
            return self._heuristic_assessment(event, reason=f"request_error:{exc}")
        except (ValueError, KeyError) as exc:
            self.log.error("Malformed LLM response, using fallback: %s", exc)
            return self._heuristic_assessment(event, reason="malformed_response")

    # -- parsing + validation ----------------------------------------------------------
    def _parse_model_json(self, text: str, model: str) -> RiskAssessment:
        cleaned = text.strip()
        cleaned = re.sub(r"^```(?:json)?|```$", "", cleaned, flags=re.MULTILINE).strip()
        data: Dict[str, Any]
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, re.DOTALL)
            if not match:
                raise ValueError("no JSON object found in model output")
            data = json.loads(match.group(0))

        score = max(0, min(100, _to_int(data.get("risk_score", 50)) or 50))
        severity = str(data.get("severity", "")).upper()
        if severity not in SEVERITY_ORDER:
            severity = self._severity_from_score(score)
        confidence = data.get("confidence", 0.5)
        try:
            confidence = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            confidence = 0.5

        return RiskAssessment(
            risk_score=score,
            severity=severity,
            intent=str(data.get("intent", "unknown")),
            verdict=str(data.get("verdict", "No verdict returned by model.")),
            recommended_action=str(data.get("recommended_action", "MONITOR")).upper(),
            mitre_technique=str(data.get("mitre_technique", "Unmapped")),
            confidence=confidence,
            model_used=model,
            raw_response=text,
        )

    @staticmethod
    def _severity_from_score(score: int) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"

    def _heuristic_assessment(self, event: SecurityEvent, reason: str) -> RiskAssessment:
        """Deterministic, rule-based triage used when the LLM is unavailable."""
        base = {
            "ssh_bruteforce": (80, "CRITICAL", "credential brute forcing", "BLOCK_IP", "T1110 Brute Force"),
            "malware_execution": (95, "CRITICAL", "remote code execution / reverse shell", "BLOCK_IP_AND_KILL", "T1059 Command and Scripting"),
            "privilege_escalation": (88, "CRITICAL", "privilege escalation", "KILL_PROCESS", "T1548 Abuse Elevation Control"),
            "webshell_activity": (90, "CRITICAL", "web shell command execution", "BLOCK_IP_AND_KILL", "T1505.003 Web Shell"),
            "web_sqli_attempt": (62, "HIGH", "SQL injection attempt", "BLOCK_IP", "T1190 Exploit Public-Facing App"),
            "network_scan": (55, "HIGH", "reconnaissance port scanning", "BLOCK_IP", "T1046 Network Service Discovery"),
            "dos_flood": (70, "HIGH", "denial of service flooding", "BLOCK_IP", "T1498 Network DoS"),
            "path_traversal": (58, "HIGH", "attempted file disclosure", "BLOCK_IP", "T1005 Data from Local System"),
            "exfiltration_attempt": (85, "CRITICAL", "data exfiltration attempt", "BLOCK_IP", "T1041 Exfiltration Over C2"),
        }
        score, severity, intent, action, mitre = base.get(
            event.event_type, (35, "MEDIUM", "suspicious anomaly", "MONITOR", "Unmapped")
        )

        # Escalate using the native Wazuh rule level as a secondary signal.
        rule_sev = wazuh_level_to_severity(event.wazuh_rule_level)
        if SEVERITY_ORDER.get(rule_sev, 0) > SEVERITY_ORDER.get(severity, 0):
            severity = rule_sev
            score = min(100, score + 10)

        return RiskAssessment(
            risk_score=score,
            severity=severity,
            intent=intent,
            verdict=(
                f"Heuristic triage (LLM unavailable: {reason}). Event '{event.event_type}' from "
                f"{event.host} involving {event.src_ip or 'an internal host'} matches a known "
                f"{intent} pattern with {severity} severity."
            ),
            recommended_action=action,
            mitre_technique=mitre,
            confidence=0.4,
            model_used="heuristic-fallback",
            raw_response="",
            fallback_used=True,
            llm_latency_ms=0,
        )


# --------------------------------------------------------------------------------------
# Section 6 :: Enforcement engine (containment playbooks)
# --------------------------------------------------------------------------------------

@dataclass
class ActionResult:
    action: str
    target: str
    success: bool
    dry_run: bool
    command: str
    detail: str
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EnforcementEngine:
    """Executes containment playbooks based on the AI risk assessment."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("autodefend.enforcement")
        self._blocklist: set[str] = set()
        self._locked: threading.Lock = threading.Lock()
        self._ensure_artifacts()
        self._load_blocklist()

    # -- setup -------------------------------------------------------------------------
    def _ensure_artifacts(self) -> None:
        Path(self.cfg.blocklist_path).touch(exist_ok=True)
        rules = Path(self.cfg.iptables_rules_path)
        if not rules.exists():
            rules.write_text(
                "# AutoDefend generated iptables rules — load with:\n"
                "#   sudo iptables-restore < autodefend_iptables.rules\n"
                "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n",
                encoding="utf-8",
            )

    def _load_blocklist(self) -> None:
        path = Path(self.cfg.blocklist_path)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                entry = line.strip()
                if entry and not entry.startswith("#"):
                    self._blocklist.add(entry)
        self.log.info("Blocklist loaded: %d existing entries", len(self._blocklist))

    # -- public entry point --------------------------------------------------------------
    def respond(self, event: SecurityEvent, assessment: RiskAssessment) -> List[ActionResult]:
        results: List[ActionResult] = []
        severity_rank = SEVERITY_ORDER.get(assessment.severity, 0)
        threshold_rank = SEVERITY_ORDER.get(self.cfg.enforce_min_severity, 3)
        should_enforce = severity_rank >= threshold_rank and assessment.severity in MITIGATION_SEVERITIES

        if not should_enforce:
            results.append(
                ActionResult(
                    action="NO_ACTION", target=event.event_id, success=True, dry_run=self.cfg.dry_run,
                    command="", detail=f"Severity {assessment.severity} below enforcement threshold "
                                     f"{self.cfg.enforce_min_severity}; monitoring only.",
                )
            )
            return results

        action = assessment.recommended_action
        if event.src_ip:
            results.append(self.block_ip(event.src_ip, event))
        if action in ("KILL_PROCESS", "BLOCK_IP_AND_KILL"):
            results.append(self.kill_process(event.pid, event.process, event))
        if action == "LOCK_ACCOUNT" and event.username:
            results.append(self.lock_account(event.username, event))
        return results

    # -- playbook 1: firewall blocklist + iptables ---------------------------------------
    def block_ip(self, ip: str, event: SecurityEvent) -> ActionResult:
        ip = str(ip).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return ActionResult("BLOCK_IP", ip, False, self.cfg.dry_run, "",
                                f"Refused: '{ip}' is not a valid IP address.")

        with self._locked:
            if ip in self._blocklist:
                return ActionResult("BLOCK_IP", ip, True, self.cfg.dry_run, "",
                                    "Idempotent: IP already present in blocklist.")
            rule_cmd = (
                f"iptables -I INPUT -s {ip} -j DROP && "
                f"iptables -I FORWARD -s {ip} -j DROP"
            )
            detail_parts = ["Appended to blocklist."]
            try:
                with open(self.cfg.blocklist_path, "a", encoding="utf-8") as fh:
                    fh.write(f"{ip}\t{utc_now()}\t{event.event_id}\t{event.event_type}\n")
                detail_parts.append(f"Blocklist updated ({self.cfg.blocklist_path}).")
            except OSError as exc:
                return ActionResult("BLOCK_IP", ip, False, self.cfg.dry_run, rule_cmd,
                                    f"Failed to append blocklist: {exc}")
            try:
                with open(self.cfg.iptables_rules_path, "a", encoding="utf-8") as fh:
                    fh.write(f"-A INPUT -s {ip} -j DROP\n-A FORWARD -s {ip} -j DROP\n")
                detail_parts.append(f"iptables rules generated ({self.cfg.iptables_rules_path}).")
            except OSError as exc:
                detail_parts.append(f"iptables rule write failed: {exc}")

            if not self.cfg.dry_run:
                exec_result = self._run_shell(rule_cmd)
                detail_parts.append(exec_result)
            else:
                detail_parts.append("DRY-RUN: iptables command not executed.")

            self._blocklist.add(ip)

        return ActionResult("BLOCK_IP", ip, True, self.cfg.dry_run, rule_cmd, " ".join(detail_parts))

    # -- playbook 2: process termination ---------------------------------------------------
    def kill_process(self, pid: Optional[int], process: Optional[str], event: SecurityEvent) -> ActionResult:
        target = f"pid={pid} process={process or 'unknown'}"
        if pid is None:
            return ActionResult("KILL_PROCESS", target, False, self.cfg.dry_run, "",
                                "No PID available for this event; skipping termination.")
        if pid in self._protected_pids():
            return ActionResult("KILL_PROCESS", target, False, self.cfg.dry_run, f"kill -9 {pid}",
                                "Refused: PID is on the protected list (safety guard).")

        cmd = f"kill -9 {pid}"
        if not self.cfg.dry_run:
            if not self._pid_exists(pid):
                return ActionResult("KILL_PROCESS", target, True, self.cfg.dry_run, cmd,
                                    "PID no longer exists (already terminated).")
            detail = self._run_shell(cmd)
        else:
            detail = "DRY-RUN: process termination not executed."
        return ActionResult("KILL_PROCESS", target, True, self.cfg.dry_run, cmd, detail)

    # -- playbook 3: account lockout -------------------------------------------------------
    def lock_account(self, username: str, event: SecurityEvent) -> ActionResult:
        username = str(username).strip()
        if not re.fullmatch(r"[A-Za-z0-9._\-]{1,32}", username):
            return ActionResult("LOCK_ACCOUNT", username, False, self.cfg.dry_run, "",
                                "Refused: username failed validation (injection guard).")
        cmd = f"passwd -l {shlex.quote(username)}"
        if not self.cfg.dry_run:
            detail = self._run_shell(cmd)
        else:
            detail = "DRY-RUN: account lockout not executed."
        return ActionResult("LOCK_ACCOUNT", username, True, self.cfg.dry_run, cmd, detail)

    # -- helpers ---------------------------------------------------------------------------
    def _protected_pids(self) -> set[int]:
        pids = set()
        for raw in self.cfg.protected_pids.split(","):
            value = _to_int(raw)
            if value is not None:
                pids.add(value)
        return pids or {1}

    @staticmethod
    def _pid_exists(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def _run_shell(self, command: str) -> str:
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=15, check=False
            )
            out = (proc.stdout or "").strip()
            err = (proc.stderr or "").strip()
            if proc.returncode == 0:
                return f"Executed OK: `{command}`" + (f" | {out}" if out else "")
            return f"Executed (rc={proc.returncode}): `{command}` | stderr: {err or 'n/a'}"
        except subprocess.TimeoutExpired:
            return f"Command timed out: `{command}`"
        except OSError as exc:
            return f"Command failed to start: {exc}"


# --------------------------------------------------------------------------------------
# Section 7 :: Persistence (SQLite + CSV live feed)
# --------------------------------------------------------------------------------------

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
    event_id            TEXT PRIMARY KEY,
    ingest_ts           TEXT NOT NULL,
    processed_ts        TEXT NOT NULL,
    source              TEXT,
    host                TEXT,
    event_type          TEXT,
    src_ip              TEXT,
    dst_ip              TEXT,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            TEXT,
    username            TEXT,
    process             TEXT,
    pid                 INTEGER,
    signature           TEXT,
    wazuh_rule_id       TEXT,
    wazuh_rule_level    INTEGER,
    raw_hash            TEXT,
    raw_json            TEXT
);

CREATE TABLE IF NOT EXISTS ai_assessments (
    event_id            TEXT PRIMARY KEY,
    risk_score          INTEGER,
    severity            TEXT,
    intent              TEXT,
    verdict             TEXT,
    recommended_action  TEXT,
    mitre_technique     TEXT,
    confidence          REAL,
    model_used          TEXT,
    fallback_used       INTEGER,
    llm_latency_ms      INTEGER,
    FOREIGN KEY(event_id) REFERENCES security_events(event_id)
);

CREATE TABLE IF NOT EXISTS mitigation_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT,
    timestamp    TEXT,
    action       TEXT,
    target       TEXT,
    success      INTEGER,
    dry_run      INTEGER,
    command      TEXT,
    detail       TEXT,
    FOREIGN KEY(event_id) REFERENCES security_events(event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_ts     ON security_events(processed_ts);
CREATE INDEX IF NOT EXISTS idx_events_sev    ON ai_assessments(severity);
CREATE INDEX IF NOT EXISTS idx_actions_ts    ON mitigation_actions(timestamp);
"""

CSV_HEADER = [
    "event_id", "processed_ts", "ingest_ts", "source", "host", "event_type",
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "username",
    "process", "pid", "signature", "wazuh_rule_id", "wazuh_rule_level",
    "risk_score", "severity", "intent", "verdict", "recommended_action",
    "mitre_technique", "confidence", "model_used", "fallback_used",
    "llm_latency_ms", "actions_summary", "raw_hash",
]


class Storage:
    """Dual-writer: authoritative SQLite ledger + flat CSV the Streamlit cockpit reads."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("autodefend.storage")
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(self.cfg.sqlite_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.executescript(SCHEMA_SQL)
        self.conn.commit()
        self._init_csv()
        self.log.info("Storage ready: SQLite=%s CSV=%s", self.cfg.sqlite_path, self.cfg.csv_path)

    def _init_csv(self) -> None:
        path = Path(self.cfg.csv_path)
        if not path.exists() or path.stat().st_size == 0:
            with path.open("w", newline="", encoding="utf-8") as fh:
                csv.writer(fh).writerow(CSV_HEADER)
        else:
            # Self-heal: if header drifted, rotate the old file and start fresh.
            with path.open("r", newline="", encoding="utf-8") as fh:
                first = fh.readline().strip().split(",")
            if first != CSV_HEADER:
                backup = path.with_suffix(f".{int(time.time())}.bak.csv")
                path.rename(backup)
                self.log.warning("CSV header mismatch; rotated old feed to %s", backup)
                with path.open("w", newline="", encoding="utf-8") as fh:
                    csv.writer(fh).writerow(CSV_HEADER)

    def record(
        self,
        event: SecurityEvent,
        assessment: RiskAssessment,
        actions: List[ActionResult],
    ) -> None:
        actions_summary = "; ".join(
            f"{a.action}:{'ok' if a.success else 'fail'}:{a.target}" for a in actions
        ) or "none"
        with self._lock:
            try:
                self.conn.execute(
                    """INSERT OR REPLACE INTO security_events
                       (event_id, ingest_ts, processed_ts, source, host, event_type, src_ip,
                        dst_ip, src_port, dst_port, protocol, username, process, pid, signature,
                        wazuh_rule_id, wazuh_rule_level, raw_hash, raw_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        event.event_id, event.ingest_ts, utc_now(), event.source, event.host,
                        event.event_type, event.src_ip, event.dst_ip, event.src_port,
                        event.dst_port, event.protocol, event.username, event.process, event.pid,
                        event.signature, event.wazuh_rule_id, event.wazuh_rule_level,
                        event.raw_hash, json.dumps(event.raw, default=str),
                    ),
                )
                self.conn.execute(
                    """INSERT OR REPLACE INTO ai_assessments
                       (event_id, risk_score, severity, intent, verdict, recommended_action,
                        mitre_technique, confidence, model_used, fallback_used, llm_latency_ms)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        event.event_id, assessment.risk_score, assessment.severity,
                        assessment.intent, assessment.verdict, assessment.recommended_action,
                        assessment.mitre_technique, assessment.confidence, assessment.model_used,
                        int(assessment.fallback_used), assessment.llm_latency_ms,
                    ),
                )
                for action in actions:
                    self.conn.execute(
                        """INSERT INTO mitigation_actions
                           (event_id, timestamp, action, target, success, dry_run, command, detail)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (
                            event.event_id, action.timestamp, action.action, action.target,
                            int(action.success), int(action.dry_run), action.command, action.detail,
                        ),
                    )
                self.conn.commit()
            except sqlite3.Error as exc:
                self.log.error("SQLite write failed: %s", exc)

            try:
                with Path(self.cfg.csv_path).open("a", newline="", encoding="utf-8") as fh:
                    csv.writer(fh).writerow([
                        event.event_id, utc_now(), event.ingest_ts, event.source, event.host,
                        event.event_type, event.src_ip, event.dst_ip, event.src_port,
                        event.dst_port, event.protocol, event.username, event.process, event.pid,
                        event.signature, event.wazuh_rule_id, event.wazuh_rule_level,
                        assessment.risk_score, assessment.severity, assessment.intent,
                        assessment.verdict, assessment.recommended_action, assessment.mitre_technique,
                        f"{assessment.confidence:.2f}", assessment.model_used,
                        int(assessment.fallback_used), assessment.llm_latency_ms,
                        actions_summary, event.raw_hash,
                    ])
            except OSError as exc:
                self.log.error("CSV append failed: %s", exc)

    def stats(self) -> Dict[str, Any]:
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM security_events")
        total = cur.fetchone()[0]
        cur.execute("SELECT severity, COUNT(*) FROM ai_assessments GROUP BY severity")
        by_sev = dict(cur.fetchall())
        cur.execute("SELECT COUNT(*) FROM mitigation_actions WHERE action != 'NO_ACTION'")
        mitigations = cur.fetchone()[0]
        return {"total_events": total, "by_severity": by_sev, "mitigations": mitigations}

    def close(self) -> None:
        with self._lock:
            self.conn.close()


# --------------------------------------------------------------------------------------
# Section 8 :: Orchestrator
# --------------------------------------------------------------------------------------

class AutoDefendSOAR:
    """Wires ingestion -> normalization -> LLM triage -> enforcement -> persistence."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.log = logging.getLogger("autodefend.soar")
        self.normalizer = LogNormalizer()
        self.analyst = OllamaAnalyst(cfg)
        self.enforcer = EnforcementEngine(cfg)
        self.storage = Storage(cfg)
        self.stop_event = threading.Event()
        self.processed = 0
        self.mitigations = 0
        self._sources: List[LogSource] = []

    # -- source selection ----------------------------------------------------------------
    def build_source(self) -> LogSource:
        if self.cfg.ingest_mode == "simulate":
            return AttackSimulator(self.cfg.simulate_interval)
        if self.cfg.ingest_mode == "file":
            return FileTailSource(self.cfg.log_file, self.cfg.poll_interval, parser="auto")
        if self.cfg.ingest_mode == "queue":
            return QueueLogSource(Queue())
        raise ValueError(f"Unknown ingest mode: {self.cfg.ingest_mode}")

    # -- main loop -----------------------------------------------------------------------
    def run(self) -> None:
        banner = {
            "service": "AutoDefend AI-SIEM SOAR Engine",
            "ingest_mode": self.cfg.ingest_mode,
            "dry_run": self.cfg.dry_run,
            "enforce_threshold": self.cfg.enforce_min_severity,
            "llm": f"{self.cfg.ollama_model} @ {self.cfg.ollama_url}",
            "sqlite": self.cfg.sqlite_path,
            "csv": self.cfg.csv_path,
        }
        self.log.info("=" * 78)
        self.log.info("AutoDefend SOAR starting")
        for key, value in banner.items():
            self.log.info("  %-18s : %s", key, value)
        self.log.info("=" * 78)
        if self.cfg.dry_run:
            self.log.warning("DRY-RUN MODE: containment playbooks will NOT modify the host. "
                             "Set AUTODEFEND_DRY_RUN=false to enforce.")

        source = self.build_source()
        self._sources.append(source)
        try:
            for raw_source, record in source.stream(self.stop_event):
                if self.stop_event.is_set():
                    break
                self.process_one(raw_source, record)
        except KeyboardInterrupt:
            self.log.info("Interrupt received, shutting down.")
        finally:
            stats = self.storage.stats()
            self.log.info("Session summary: %s", json.dumps(stats))
            for src in self._sources:
                src.close()
            self.storage.close()

    # -- per-event pipeline ---------------------------------------------------------------
    def process_one(self, raw_source: str, record: Any) -> None:
        event = self.normalizer.normalize(raw_source, record)
        if event is None:
            return
        self.processed += 1
        self.log.info(
            "EVENT %s | %s | host=%s src=%s type=%s (rule %s/%s)",
            event.event_id, raw_source.upper(), event.host, event.src_ip or "-",
            event.event_type, event.wazuh_rule_id or "-", event.wazuh_rule_level or "-",
        )

        assessment = self.analyst.assess(event)
        self.log.info(
            "TRIAGE | score=%d severity=%s action=%s fallback=%s (%dms) | %s",
            assessment.risk_score, assessment.severity, assessment.recommended_action,
            assessment.fallback_used, assessment.llm_latency_ms, assessment.intent,
        )
        self.log.info("VERDICT | %s", assessment.verdict)

        actions = self.enforcer.respond(event, assessment)
        for action in actions:
            flag = "OK" if action.success else "FAIL"
            if action.action != "NO_ACTION":
                self.mitigations += 1
            self.log.info(
                "ACTION | [%s] %s -> %s :: %s", flag, action.action, action.target, action.detail
            )

        self.storage.record(event, assessment, actions)
        return None

    def shutdown(self, *_args: Any) -> None:
        self.log.warning("Shutdown signal received — draining pipeline...")
        self.stop_event.set()


# --------------------------------------------------------------------------------------
# Section 9 :: CLI
# --------------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="autodefend_backend.py",
        description="AutoDefend AI-SIEM SOAR engine: Wazuh/Syslog -> Ollama triage -> auto-containment.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--mode", choices=["simulate", "file", "queue"],
                        help="Ingestion mode (overrides AUTODEFEND_INGEST_MODE).")
    parser.add_argument("--log-file", help="Path to Wazuh alerts.json / syslog file (file mode).")
    parser.add_argument("--model", help="Ollama model name (e.g. llama3, mistral, phi3).")
    parser.add_argument("--ollama-url", help="Ollama generate endpoint URL.")
    parser.add_argument("--interval", type=float, help="Simulator/poll interval in seconds.")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true", default=None,
                        help="Force dry-run (no host changes).")
    parser.add_argument("--enforce", dest="dry_run", action="store_false",
                        help="Force live enforcement (executes real containment).")
    parser.add_argument("--max-events", type=int, default=0,
                        help="Stop after N events (0 = run forever). Useful for CI/tests.")
    parser.add_argument("--stats", action="store_true",
                        help="Print the SQLite ledger summary and exit (no ingestion).")
    parser.add_argument("--db", help="SQLite database path.")
    parser.add_argument("--csv", help="CSV live-feed path.")
    parser.add_argument("--log-level", help="DEBUG|INFO|WARNING|ERROR")
    return parser


def config_from_args(args: argparse.Namespace) -> Config:
    cfg = Config()
    if args.mode:
        cfg.ingest_mode = args.mode
    if args.log_file:
        cfg.log_file = args.log_file
    if args.model:
        cfg.ollama_model = args.model
    if args.ollama_url:
        cfg.ollama_url = args.ollama_url
    if args.interval is not None:
        cfg.simulate_interval = args.interval
        cfg.poll_interval = args.interval
    if args.dry_run is not None:
        cfg.dry_run = args.dry_run
    if args.db:
        cfg.sqlite_path = args.db
    if args.csv:
        cfg.csv_path = args.csv
    if args.log_level:
        cfg.log_level = args.log_level.upper()
    return cfg


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = config_from_args(args)

    global LOG
    LOG = configure_logging(cfg.log_level)

    if args.stats:
        storage = Storage(cfg)
        print(json.dumps(storage.stats(), indent=2))
        storage.close()
        return 0

    soar = AutoDefendSOAR(cfg)
    signal.signal(signal.SIGINT, soar.shutdown)
    signal.signal(signal.SIGTERM, soar.shutdown)

    if args.max_events and args.max_events > 0:
        original = soar.process_one
        counter = {"n": 0}

        def capped(raw_source: str, record: Any) -> None:
            if counter["n"] >= args.max_events:
                soar.stop_event.set()
                return
            original(raw_source, record)
            counter["n"] += 1
            if counter["n"] >= args.max_events:
                soar.stop_event.set()

        soar.process_one = capped  # type: ignore[assignment]

    soar.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
