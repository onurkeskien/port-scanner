#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

VERSION = "1.2"


# ===============================
# Language system
# ===============================

LANGUAGES = {
    "en": {
        "select_lang": "Select language / Sprache wählen / Dil seçin:",
        "lang_options": "1) English\n2) Deutsch\n3) Türkçe",
        "target": "Target IP/Host (e.g. 127.0.0.1 or 192.168.1.0/24): ",
        "ports": 'Ports (e.g. "80" or "22,80,443" or "1-1024"): ',
        "threads": "Threads (e.g. 200): ",
        "timeout": "Timeout seconds (e.g. 0.6): ",
        "banner_q": "Banner grabbing? (y/N): ",
        "open_only_q": "Print only open ports? (y/N): ",
        "export_txt_q": "Export open ports to TXT? (y/N): ",
        "export_csv_q": "Export full results to CSV? (y/N): ",
        "txt_path": "TXT path (e.g. open_ports.txt): ",
        "csv_path": "CSV path (e.g. scan.csv): ",
        "scanning": "Scanning",
        "done": "Scan completed.",
        "open_found": "Open ports found:",
        "no_open": "No open ports found.",
        "saved_txt": "Saved TXT ->",
        "saved_csv": "Saved CSV ->",
        "invalid": "Invalid input, using default.",
        "summary": "Summary",
    },
    "de": {
        "select_lang": "Sprache auswählen:",
        "lang_options": "1) English\n2) Deutsch\n3) Türkçe",
        "target": "Ziel IP/Host (z.B. 127.0.0.1 oder 192.168.1.0/24): ",
        "ports": 'Ports (z.B. "80" oder "22,80,443" oder "1-1024"): ',
        "threads": "Threads (z.B. 200): ",
        "timeout": "Timeout Sekunden (z.B. 0.6): ",
        "banner_q": "Banner grabbing? (j/N): ",
        "open_only_q": "Nur offene Ports anzeigen? (j/N): ",
        "export_txt_q": "Offene Ports als TXT exportieren? (j/N): ",
        "export_csv_q": "Alle Ergebnisse als CSV exportieren? (j/N): ",
        "txt_path": "TXT Pfad (z.B. open_ports.txt): ",
        "csv_path": "CSV Pfad (z.B. scan.csv): ",
        "scanning": "Scanne",
        "done": "Scan abgeschlossen.",
        "open_found": "Offene Ports:",
        "no_open": "Keine offenen Ports gefunden.",
        "saved_txt": "TXT gespeichert ->",
        "saved_csv": "CSV gespeichert ->",
        "invalid": "Ungültige Eingabe, Standard wird verwendet.",
        "summary": "Zusammenfassung",
    },
    "tr": {
        "select_lang": "Dil seçin:",
        "lang_options": "1) English\n2) Deutsch\n3) Türkçe",
        "target": "Hedef IP/Host (örn: 127.0.0.1 veya 192.168.1.0/24): ",
        "ports": 'Portlar (örn: "80" veya "22,80,443" veya "1-1024"): ',
        "threads": "Thread sayısı (örn: 200): ",
        "timeout": "Timeout saniye (örn: 0.6): ",
        "banner_q": "Banner çekilsin mi? (e/H): ",
        "open_only_q": "Sadece açık portlar yazılsın mı? (e/H): ",
        "export_txt_q": "Açık portları TXT olarak kaydet? (e/H): ",
        "export_csv_q": "Tüm sonuçları CSV olarak kaydet? (e/H): ",
        "txt_path": "TXT dosya yolu (örn: open_ports.txt): ",
        "csv_path": "CSV dosya yolu (örn: scan.csv): ",
        "scanning": "Taranıyor",
        "done": "Tarama tamamlandı.",
        "open_found": "Açık portlar:",
        "no_open": "Açık port bulunamadı.",
        "saved_txt": "TXT kaydedildi ->",
        "saved_csv": "CSV kaydedildi ->",
        "invalid": "Geçersiz giriş, varsayılan kullanılacak.",
        "summary": "Özet",
    },
}


def choose_language_interactive() -> str:
    print(LANGUAGES["en"]["select_lang"])
    print(LANGUAGES["en"]["lang_options"])
    sel = input("> ").strip()
    if sel == "2":
        return "de"
    if sel == "3":
        return "tr"
    return "en"

# ===============================
# Banner
# ===============================

def print_banner() -> None:
    # PORT SCANNER ASCII style (clean / red-team minimal)
    print("\n")
    print("########################################################")
    print("#                                                      #")
    print("#           ██████   ██████  ██████  ████████          #")
    print("#           ██   ██ ██    ██ ██   ██    ██             #")
    print("#           ██████  ██    ██ ██████     ██             #")
    print("#           ██      ██    ██ ██   ██    ██             #")
    print("#           ██       ██████  ██   ██    ██             #")
    print("#                                                      #")
    print("#                 PORT SCANNER                         #")
    print("#                 Onur Keskin                          #")
    print("#                    v.1.0                             #")
    print("#                                                      #")
    print("########################################################\n")

# ===============================
# Output color (optional)
# ===============================

def supports_color() -> bool:
    if sys.platform.startswith("win"):
        # Windows Terminal / modern consoles usually ok; still allow disabling via --no-color
        return True
    return sys.stdout.isatty()


def c(text: str, code: str, enable: bool) -> str:
    if not enable:
        return text
    return f"\033[{code}m{text}\033[0m"


# ===============================
# Parsing helpers
# ===============================

def parse_targets(target: str) -> list[str]:
    """
    Accepts:
      - Single IP: 192.168.1.10
      - CIDR: 192.168.1.0/24
      - Hostname: example.local
    """
    target = target.strip()
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [target]


def parse_ports(ports: str) -> list[int]:
    """
    Accepts:
      - "80"
      - "22,80,443"
      - "1-1024"
      - "22,80,443,8000-8100"
    """
    out: set[int] = set()
    parts = [p.strip() for p in ports.split(",") if p.strip()]
    for part in parts:
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                start, end = end, start
            for port in range(start, end + 1):
                if 1 <= port <= 65535:
                    out.add(port)
        else:
            port = int(part)
            if 1 <= port <= 65535:
                out.add(port)
    return sorted(out)


def guess_service(port: int) -> str:
    # quick common mapping; fallback to getservbyport where possible
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
        135: "msrpc", 139: "netbios-ssn", 143: "imap",
        443: "https", 445: "microsoft-ds", 3389: "rdp",
        3306: "mysql", 5432: "postgres", 6379: "redis",
        1883: "mqtt", 502: "modbus", 20000: "dnp3",
    }
    if port in common:
        return common[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return ""


# ===============================
# Scanner core
# ===============================

@dataclass
class ScanResult:
    host: str
    port: int
    state: str          # "open" | "closed"
    service: str = ""
    banner: str = ""


def try_banner(sock: socket.socket, host: str, port: int, timeout_s: float) -> str:
    """
    Best-effort banner grab. Keeps it small and safe:
    - For HTTP-ish ports, send minimal HEAD.
    - Otherwise, just recv if server speaks first.
    """
    sock.settimeout(timeout_s)

    if port in (80, 8080, 8000, 8888, 443):
        try:
            req = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii", errors="ignore")
            sock.sendall(req)
        except Exception:
            pass

    try:
        data = sock.recv(256)
        if not data:
            return ""
        text = data.decode("utf-8", errors="replace").strip()
        return " ".join(text.split())
    except Exception:
        return ""


def scan_one(host: str, port: int, timeout_s: float, do_banner: bool) -> ScanResult:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_s)
    try:
        rc = s.connect_ex((host, port))
        if rc == 0:
            service = guess_service(port)
            banner = try_banner(s, host, port, timeout_s) if do_banner else ""
            return ScanResult(host=host, port=port, state="open", service=service, banner=banner)
        return ScanResult(host=host, port=port, state="closed", service=guess_service(port) or "")
    except Exception:
        return ScanResult(host=host, port=port, state="closed", service=guess_service(port) or "")
    finally:
        try:
            s.close()
        except Exception:
            pass


def iter_jobs(hosts: Iterable[str], ports: Iterable[int]) -> Iterable[tuple[str, int]]:
    for h in hosts:
        for p in ports:
            yield (h, p)


# ===============================
# Export
# ===============================

def export_txt_open(results: list[ScanResult], out_path: Path) -> None:
    lines = []
    for r in results:
        if r.state == "open":
            line = f"{r.host}:{r.port}"
            if r.service:
                line += f" ({r.service})"
            if r.banner:
                line += f" | {r.banner}"
            lines.append(line)
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def export_csv_all(results: list[ScanResult], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "state", "service", "banner"])
        for r in results:
            w.writerow([r.host, r.port, r.state, r.service, r.banner])


# ===============================
# Interactive mode
# ===============================

def interactive_mode() -> dict:
    lang_key = choose_language_interactive()
    L = LANGUAGES[lang_key]

    target = input(L["target"]).strip()
    ports = input(L["ports"]).strip() or "1-1024"

    def read_int(prompt: str, default: int) -> int:
        raw = input(prompt).strip()
        if not raw:
            return default
        try:
            return int(raw)
        except Exception:
            print(L["invalid"])
            return default

    def read_float(prompt: str, default: float) -> float:
        raw = input(prompt).strip()
        if not raw:
            return default
        try:
            return float(raw)
        except Exception:
            print(L["invalid"])
            return default

    threads = read_int(L["threads"], 200)
    timeout_s = read_float(L["timeout"], 0.6)

    banner = input(L["banner_q"]).strip().lower() in ("y", "yes", "j", "ja", "e", "evet")
    open_only = input(L["open_only_q"]).strip().lower() in ("y", "yes", "j", "ja", "e", "evet")

    out_txt = None
    out_csv = None
    if input(L["export_txt_q"]).strip().lower() in ("y", "yes", "j", "ja", "e", "evet"):
        out_txt = input(L["txt_path"]).strip() or "open_ports.txt"
    if input(L["export_csv_q"]).strip().lower() in ("y", "yes", "j", "ja", "e", "evet"):
        out_csv = input(L["csv_path"]).strip() or "scan.csv"

    return {
        "lang": lang_key,
        "target": target,
        "ports": ports,
        "threads": threads,
        "timeout": timeout_s,
        "banner": banner,
        "open_only": open_only,
        "out_txt": out_txt,
        "out_csv": out_csv,
        "no_banner": False,
        "no_color": False,
    }


# ===============================
# CLI args (professional mode)
# ===============================

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Simple TCP Port Scanner (use only on your own/authorized lab systems)."
    )
    ap.add_argument("target", nargs="?", default=None, help="IP, CIDR (e.g. 192.168.1.0/24) or hostname")
    ap.add_argument("--ports", default="1-1024", help='Ports: "80" or "22,80,443" or "1-1024"')
    ap.add_argument("--threads", type=int, default=200, help="Worker threads")
    ap.add_argument("--timeout", type=float, default=0.6, help="Socket timeout seconds")
    ap.add_argument("--banner", action="store_true", help="Try to grab a small banner on open ports")
    ap.add_argument("--open-only", action="store_true", help="Print only open ports")
    ap.add_argument("--out-txt", type=str, default=None, help="Export open ports to TXT")
    ap.add_argument("--out-csv", type=str, default=None, help="Export all results to CSV")
    ap.add_argument("--lang", choices=["en", "de", "tr"], default=None, help="UI language")
    ap.add_argument("--no-banner", action="store_true", help="Disable startup banner")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--interactive", action="store_true", help="Run interactive mode")
    ap.add_argument("--version", action="store_true", help="Print version and exit")
    return ap.parse_args()


# ===============================
# Main
# ===============================

def main() -> int:
    args = parse_args()

    if args.version:
        print(f"PORT SCANNER - Onur Keskin - v{VERSION}")
        return 0

    # Decide mode
    if args.interactive or args.target is None:
        cfg = interactive_mode()
        lang_key = cfg["lang"]
        target = cfg["target"]
        ports_str = cfg["ports"]
        threads = cfg["threads"]
        timeout_s = cfg["timeout"]
        do_banner_grab = cfg["banner"]
        open_only = cfg["open_only"]
        out_txt = cfg["out_txt"]
        out_csv = cfg["out_csv"]
        no_banner = cfg["no_banner"]
        no_color = cfg["no_color"]
    else:
        lang_key = args.lang or "en"
        target = args.target
        ports_str = args.ports
        threads = max(1, int(args.threads))
        timeout_s = float(args.timeout)
        do_banner_grab = bool(args.banner)
        open_only = bool(args.open_only)
        out_txt = args.out_txt
        out_csv = args.out_csv
        no_banner = bool(args.no_banner)
        no_color = bool(args.no_color)

    L = LANGUAGES[lang_key]

    color_on = supports_color() and (not no_color)

    # Banner only at startup (and can be disabled)
    if not no_banner:
        print_banner()

    hosts = parse_targets(target)
    ports = parse_ports(ports_str)

    if not hosts:
        print("No hosts parsed.", file=sys.stderr)
        return 2
    if not ports:
        print("No ports parsed.", file=sys.stderr)
        return 2

    total = len(hosts) * len(ports)
    start_ts = time.time()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"{L['scanning']} {len(hosts)} host(s) x {len(ports)} port(s) = {total} checks")
    print(f"Time: {now}")
    print("-" * 60)

    results: list[ScanResult] = []
    completed = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [
            ex.submit(scan_one, host, port, timeout_s, do_banner_grab)
            for (host, port) in iter_jobs(hosts, ports)
        ]

        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            completed += 1

            # Print
            if open_only and r.state != "open":
                continue

            if r.state == "open":
                tag = c("[OPEN]", "92", color_on)  # green
                svc = f" ({r.service})" if r.service else ""
                msg = f"{tag} {r.host}:{r.port}{svc}"
                if r.banner:
                    msg += f" | {r.banner}"
                print(msg)
            else:
                tag = c("[closed]", "90", color_on)  # gray
                svc = f" ({r.service})" if r.service else ""
                print(f"{tag} {r.host}:{r.port}{svc}")

            # Light progress every ~5%
            if total >= 200 and completed % max(1, total // 20) == 0:
                pct = int((completed / total) * 100)
                print(c(f"-- progress: {pct}% ({completed}/{total}) --", "94", color_on))

    results.sort(key=lambda x: (x.host, x.port))
    open_results = [r for r in results if r.state == "open"]

    elapsed = time.time() - start_ts

    print("-" * 60)
    print(f"{L['done']}")
    print(f"{L['summary']}: open {len(open_results)}/{len(results)} | threads={threads} | timeout={timeout_s}s | elapsed={elapsed:.2f}s")

    if open_results:
        # concise list
        ports_by_host: dict[str, list[int]] = {}
        for r in open_results:
            ports_by_host.setdefault(r.host, []).append(r.port)
        print(f"{L['open_found']}")
        for h, ps in ports_by_host.items():
            print(f"  {h}: {ps}")
    else:
        print(L["no_open"])

    # Export
    if out_txt:
        export_txt_open(results, Path(out_txt))
        print(f"{L['saved_txt']} {out_txt}")
    if out_csv:
        export_csv_all(results, Path(out_csv))
        print(f"{L['saved_csv']} {out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
