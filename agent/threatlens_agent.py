"""ThreatLens Windows endpoint agent. Run from an elevated terminal for real enforcement."""

import hashlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sqlite3
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
import time
import urllib.error
import urllib.request


SERVER = os.environ.get("THREATLENS_SERVER", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("THREATLENS_AGENT_TOKEN", "")
AGENT_ID = os.environ.get("THREATLENS_AGENT_ID", socket.gethostname())
VERSION = "1.0.0"
CAPABILITIES = ["firewall.block_ip", "firewall.unblock_ip", "telemetry.sysmon", "telemetry.eventlog", "telemetry.syslog", "telemetry.journald"]
PROTECTED = {item.strip() for item in os.environ.get("THREATLENS_PROTECTED_ADDRESSES", "127.0.0.1,::1").split(",") if item.strip()}
QUEUE_PATH = os.environ.get("THREATLENS_QUEUE_PATH", "threatlens-agent.db")
QUEUE_LIMIT = int(os.environ.get("THREATLENS_QUEUE_LIMIT", "5000"))
BATCH_SIZE = min(100, int(os.environ.get("THREATLENS_BATCH_SIZE", "50")))
COLLECTION_INTERVAL = max(2, int(os.environ.get("THREATLENS_COLLECTION_INTERVAL", "5")))


def utc_iso(value=None):
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


class OfflineQueue:
    def __init__(self, path=QUEUE_PATH, limit=QUEUE_LIMIT):
        self.limit = limit
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS queue (event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.commit()

    def put(self, event):
        self.db.execute("INSERT OR IGNORE INTO queue VALUES (?, ?, ?)", (event["event_id"], json.dumps(event), utc_iso()))
        excess = self.db.execute("SELECT COUNT(*) FROM queue").fetchone()[0] - self.limit
        if excess > 0:
            self.db.execute("DELETE FROM queue WHERE event_id IN (SELECT event_id FROM queue ORDER BY created_at LIMIT ?)", (excess,))
        self.db.commit()

    def batch(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM queue ORDER BY created_at LIMIT ?", (BATCH_SIZE,)).fetchall()]

    def acknowledge(self, event_ids):
        self.db.executemany("DELETE FROM queue WHERE event_id = ?", [(value,) for value in event_ids])
        self.db.commit()

    def state(self, key, default=None):
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default

    def set_state(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, str(value)))
        self.db.commit()


def xml_fields(xml_text):
    root = ET.fromstring(xml_text)
    system = root.find("./{*}System")
    fields = {item.attrib.get("Name", ""): item.text for item in root.findall("./{*}EventData/{*}Data")}
    event_id = system.findtext("./{*}EventID")
    record_id = system.findtext("./{*}EventRecordID") or hashlib.sha256(xml_text.encode()).hexdigest()[:24]
    created = system.find("./{*}TimeCreated")
    timestamp = created.attrib.get("SystemTime") if created is not None else utc_iso()
    channel = system.findtext("./{*}Channel") or "unknown"
    computer = system.findtext("./{*}Computer") or socket.gethostname()
    return int(event_id), record_id, timestamp, channel, computer, fields


def normalized_event(event_id, timestamp, source, event_type, source_ip=None, username=None, message=None, metadata=None):
    return {
        "event_id": str(event_id), "timestamp": timestamp, "telemetry_source": source,
        "event_type": event_type, "source_ip": source_ip, "username": username,
        "severity": None, "message": (message or "")[:2000], "metadata": metadata or {},
    }


def normalize_sysmon(xml_text):
    event_code, record_id, timestamp, channel, computer, data = xml_fields(xml_text)
    mapping = {1: "process_creation", 3: "network_connection", 5: "process_termination", 11: "file_create", 22: "dns_query"}
    event_type = mapping.get(event_code)
    if not event_type:
        return None
    source_ip = data.get("SourceIp")
    command = data.get("CommandLine") or data.get("Image") or data.get("QueryName") or data.get("TargetFilename")
    metadata = {
        "platform_event_id": event_code, "hostname": computer, "destination_ip": data.get("DestinationIp"),
        "source_port": data.get("SourcePort"), "destination_port": data.get("DestinationPort"),
        "protocol": data.get("Protocol"), "process": data.get("Image"), "process_id": data.get("ProcessId"),
        "parent_process": data.get("ParentImage"), "dns_query": data.get("QueryName"), "file_path": data.get("TargetFilename"),
    }
    return normalized_event(f"{channel}:{record_id}", timestamp, "sysmon", event_type, source_ip, data.get("User"), command, {k: v for k, v in metadata.items() if v is not None})


def normalize_windows_event(xml_text):
    event_code, record_id, timestamp, channel, computer, data = xml_fields(xml_text)
    security = {4624: "login_success", 4625: "login_failed", 4720: "account_created", 4726: "account_deleted", 4732: "account_group_changed"}
    system = {7045: "service_installed", 7036: "service_state_change"}
    event_type = (security if "Security" in channel else system).get(event_code)
    if not event_type:
        return None
    source = "windows_security" if "Security" in channel else "windows_system"
    source_ip = data.get("IpAddress")
    if source_ip in {"-", "::1", "127.0.0.1"}:
        source_ip = None
    username = data.get("TargetUserName") or data.get("SubjectUserName")
    metadata = {"platform_event_id": event_code, "hostname": computer, "logon_type": data.get("LogonType"), "process": data.get("ProcessName"), "service_name": data.get("ServiceName")}
    message = f"Windows event {event_code}: {event_type} for {username or 'unknown account'}"
    return normalized_event(f"{channel}:{record_id}", timestamp, source, event_type, source_ip, username, message, {k: v for k, v in metadata.items() if v is not None})


SYSLOG_RE = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<program>[^:\[]+)(?:\[\d+\])?:\s*(?P<message>.*)$")


def normalize_linux_message(message, event_id=None, timestamp=None, source="syslog", metadata=None):
    match = SYSLOG_RE.match(message)
    body = match.group("message") if match else message
    lower = body.lower()
    source_match = re.search(r"from\s+([0-9a-fA-F:.]+)", body)
    source_ip = source_match.group(1) if source_match else None
    user_match = re.search(r"for (?:invalid user )?(\S+)", body, re.IGNORECASE)
    username = user_match.group(1) if user_match else None
    if "failed password" in lower or "authentication failure" in lower:
        event_type = "ssh_failed_login"
    elif "accepted password" in lower or "accepted publickey" in lower:
        event_type = "ssh_success"
    elif "command=" in lower or "sudo:" in lower:
        event_type = "command_execution"
    else:
        event_type = "system_message"
    stable_id = event_id or hashlib.sha256(message.encode()).hexdigest()
    return normalized_event(stable_id, timestamp or utc_iso(), source, event_type, source_ip, username, body, metadata)


def request(method, path, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{SERVER}{path}", data=body, method=method,
        headers={"X-Agent-Token": TOKEN, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode())


def local_ips():
    return sorted({item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None) if item[0] in (socket.AF_INET, socket.AF_INET6)})


def validate_target(value):
    address = ipaddress.ip_address(value)
    if address.is_loopback or address.is_unspecified or address.is_multicast or str(address) in PROTECTED:
        raise ValueError("Protected IP address")
    return str(address)


def expected_rule_name(target):
    return f"ThreatLens-{hashlib.sha256(target.encode('ascii')).hexdigest()[:16]}"


def powershell(arguments):
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", *arguments],
        capture_output=True, text=True, timeout=20, check=False,
    )


def execute(task):
    target = validate_target(task["target"])
    rule = task["managed_rule_id"]
    if rule != expected_rule_name(target):
        raise ValueError("Invalid managed rule identifier")
    if task["action"] == "block_source_ip":
        command = ["New-NetFirewallRule", "-DisplayName", rule, "-Direction", "Inbound", "-Action", "Block", "-RemoteAddress", target, "-Profile", "Any"]
        verify = ["Get-NetFirewallRule", "-DisplayName", rule, "-ErrorAction", "SilentlyContinue"]
        expected_present = True
    elif task["action"] == "unblock_source_ip":
        command = ["Remove-NetFirewallRule", "-DisplayName", rule, "-ErrorAction", "SilentlyContinue"]
        verify = ["Get-NetFirewallRule", "-DisplayName", rule, "-ErrorAction", "SilentlyContinue"]
        expected_present = False
    else:
        raise ValueError("Unsupported action")
    result = powershell(command)
    check = powershell(verify)
    present = bool(check.stdout.strip())
    verified = result.returncode == 0 and present is expected_present
    return {
        "status": "completed" if verified else "failed",
        "result": {"return_code": result.returncode, "managed_rule_id": rule, "stderr": result.stderr[-500:]},
        "verification_result": {"verified": verified, "method": "Windows Firewall rule lookup", "rule_present": present},
    }


def collect_windows(queue):
    since = queue.state("windows_since", (datetime.now(timezone.utc).timestamp() - 30))
    start = datetime.fromtimestamp(float(since), timezone.utc).isoformat()
    script = (
        "$start=[datetime]::Parse('" + start + "');"
        "$logs=@('Microsoft-Windows-Sysmon/Operational','Security','System');"
        "$items=foreach($log in $logs){Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$start} -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {$_.ToXml()}};"
        "$items | ConvertTo-Json -Compress"
    )
    result = powershell([script])
    if result.returncode != 0 or not result.stdout.strip():
        return
    values = json.loads(result.stdout)
    for xml_text in ([values] if isinstance(values, str) else values):
        try:
            event = normalize_sysmon(xml_text) if "Sysmon" in xml_text else normalize_windows_event(xml_text)
            if event:
                queue.put(event)
        except (ET.ParseError, ValueError, TypeError):
            continue
    queue.set_state("windows_since", datetime.now(timezone.utc).timestamp())


def collect_journald(queue):
    since = queue.state("journal_since", str(int(datetime.now(timezone.utc).timestamp()) - 30))
    result = subprocess.run(
        ["journalctl", "--since", f"@{since}", "--output=json", "--no-pager", "-n", "200"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if result.returncode != 0:
        return False
    newest = since
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
            micros = int(item.get("__REALTIME_TIMESTAMP", "0"))
            timestamp = datetime.fromtimestamp(micros / 1_000_000, timezone.utc).isoformat() if micros else utc_iso()
            event = normalize_linux_message(
                item.get("MESSAGE", ""), event_id=item.get("__CURSOR"), timestamp=timestamp,
                source="journald", metadata={"unit": item.get("_SYSTEMD_UNIT"), "process": item.get("SYSLOG_IDENTIFIER")},
            )
            queue.put(event)
            newest = str(max(int(newest), int(micros / 1_000_000)))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    queue.set_state("journal_since", newest)
    return True


def collect_syslog(queue):
    for path in ("/var/log/auth.log", "/var/log/secure", "/var/log/syslog"):
        if not os.path.isfile(path):
            continue
        key = f"offset:{path}"
        offset = int(queue.state(key, "0"))
        size = os.path.getsize(path)
        if offset > size:
            offset = 0
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            while True:
                line = handle.readline()
                if not line:
                    break
                text = line.rstrip()
                queue.put(normalize_linux_message(text, event_id=hashlib.sha256(f"{path}:{offset}:{text}".encode()).hexdigest(), source="syslog", metadata={"file": path}))
                offset = handle.tell()
        queue.set_state(key, offset)


def flush_events(queue):
    batch = queue.batch()
    if not batch:
        return
    result = request("POST", f"/api/v1/agents/{AGENT_ID}/events/batch", {"events": batch})
    acknowledged = [item["event_id"] for item in result.get("accepted", [])] + result.get("duplicates", [])
    queue.acknowledge(acknowledged)


def main():
    if not TOKEN:
        raise SystemExit("THREATLENS_AGENT_TOKEN is required")
    queue = OfflineQueue()
    registration = {"agent_id": AGENT_ID, "hostname": socket.gethostname(), "os": platform.platform(), "ip_addresses": local_ips(), "version": VERSION, "capabilities": CAPABILITIES}
    while True:
        try:
            request("POST", "/api/v1/agents/register", registration)
            if platform.system() == "Windows":
                collect_windows(queue)
            elif not collect_journald(queue):
                collect_syslog(queue)
            flush_events(queue)
            response = request("GET", f"/api/v1/agents/{AGENT_ID}/tasks/next")
            task = response.get("task")
            if task:
                try:
                    outcome = execute(task)
                except Exception as exc:
                    outcome = {"status": "failed", "result": {"error": str(exc)}, "verification_result": {"verified": False, "method": "agent validation"}}
                request("POST", f"/api/v1/agents/{AGENT_ID}/tasks/{task['id']}/result", outcome)
            else:
                request("POST", f"/api/v1/agents/{AGENT_ID}/heartbeat")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            pass
        time.sleep(COLLECTION_INTERVAL)


if __name__ == "__main__":
    main()
