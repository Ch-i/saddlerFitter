"""Network watch → status badges, refreshed every X.

Privilege-free by default: live socket/throughput/exposure telemetry from `ss` +
/proc/net/dev — no capture privilege needed. If tcpdump is granted cap_net_raw
(one-time `sudo setcap cap_net_raw+ep $(which tcpdump)`, or Wireshark + the
`wireshark` group), a deep mode adds packet-level protocol/talker badges — the true
Wireshark view. The watch is stateful so it can derive throughput between samples.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time

# Explicit capture interface for deep mode (e.g. an AWUS set to monitor: wlx...).
# Monitor-mode 802.11 capture is an authorized opt-in — point this only at networks
# you own or are authorized to audit.
CAP_IFACE = os.environ.get("SADDLER_CAP_IFACE", "")


def _run(cmd, timeout=4):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def _deep_available() -> bool:
    td = shutil.which("tcpdump") or ""
    return bool(td) and "cap_net_raw" in _run(["getcap", td])


def _human_rate(b: float) -> str:
    for u in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.0f} {u}/s"
        b /= 1024
    return f"{b:.1f} TB/s"


def _loopback(addr: str) -> bool:
    return addr.startswith(("127.", "[::1]", "[::ffff:127"))


class NetWatch:
    def __init__(self):
        self._prev = None

    def _ifaces(self) -> dict:
        out = {}
        try:
            with open("/proc/net/dev") as fh:
                for ln in fh.readlines()[2:]:
                    name, rest = ln.split(":", 1)
                    name = name.strip()
                    if name == "lo" or name.startswith(("virbr", "docker", "br-", "veth")):
                        continue
                    c = rest.split()
                    out[name] = {"rx": int(c[0]), "tx": int(c[8])}
        except Exception:
            pass
        return out

    def sample(self) -> dict:
        ss_s = _run(["ss", "-s"])
        m = re.search(r"TCP:\s+(\d+)\s+\(estab\s+(\d+)", ss_s)
        total = int(m.group(1)) if m else 0
        estab = int(m.group(2)) if m else 0
        listeners = [p.split()[3] for p in _run(["ss", "-tlnH"]).splitlines() if len(p.split()) >= 4]
        exposed = [a for a in listeners if not _loopback(a)]
        ifaces = self._ifaces()
        rx = sum(i["rx"] for i in ifaces.values())
        tx = sum(i["tx"] for i in ifaces.values())
        return {"t": time.time(), "total": total, "estab": estab,
                "listeners": len(listeners), "exposed": exposed, "rx": rx, "tx": tx}

    def badges(self) -> dict:
        s = self.sample()
        rate = 0.0
        if self._prev:
            dt = max(0.001, s["t"] - self._prev["t"])
            rate = ((s["rx"] - self._prev["rx"]) + (s["tx"] - self._prev["tx"])) / dt
        self._prev = s
        deep = _deep_available()
        badges = [
            {"label": "sockets", "value": str(s["total"]), "level": "ok"},
            {"label": "established", "value": str(s["estab"]), "level": "ok"},
            {"label": "throughput", "value": _human_rate(rate), "level": "ok"},
            {"label": "exposed", "value": str(len(s["exposed"])),
             "level": "warn" if s["exposed"] else "ok"},
            {"label": "capture", "value": "deep" if deep else "telemetry",
             "level": "ok" if deep else "dim"},
        ]
        return {"badges": badges, "exposed": sorted(set(s["exposed"]))[:14], "deep": deep}

    def _primary_iface(self) -> str:
        ifs = self._ifaces()
        return max(ifs, key=lambda k: ifs[k]["rx"], default="any") if ifs else "any"

    def deep_sample(self, seconds: int = 3) -> dict | None:
        """Packet-level protocol summary — only when capture is granted (cap_net_raw
        on tcpdump/dumpcap). Captures CAP_IFACE, else the busiest host interface."""
        if not _deep_available():
            return None
        iface = CAP_IFACE or self._primary_iface()
        ts = shutil.which("tshark")
        if ts:
            out = _run([ts, "-i", iface, "-a", f"duration:{seconds}", "-q", "-z", "io,phs"],
                       timeout=seconds + 5)
            protos = re.findall(r"^\s*([a-z0-9_.:-]+)\s+frames:(\d+)", out, re.M)
            top = sorted(protos, key=lambda x: int(x[1]), reverse=True)[:5]
            return {"iface": iface, "protocols": [{"name": n, "frames": int(f)} for n, f in top]}
        td = shutil.which("tcpdump")
        if td:
            out = _run([td, "-i", iface, "-c", "300", "-nn", "-q"], timeout=seconds + 5)
            return {"iface": iface, "packets": out.count("\n")}
        return None
