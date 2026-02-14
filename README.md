# PORT SCANNER (TCP)

A simple multi-language TCP Port Scanner developed in Python.

Author: **Onur Keskin**\
Version: **1.0**

## Disclaimer

This tool is intended for educational purposes and authorized lab
environments only.\
Use it only on systems you own or have explicit permission to test.

## Features

-   Multi-language support (English / Deutsch / Türkçe)
-   TCP Port Scanning
-   Single IP, CIDR range, or hostname support
-   Threaded scanning (fast)
-   Optional banner grabbing
-   Basic service detection
-   TXT export (open ports)
-   CSV export (full results)
-   Colored terminal output
-   Interactive mode
-   Professional CLI mode

## Installation

It is recommended to use a virtual environment.

### macOS / Linux

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

### Windows (PowerShell)

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

## Usage

Make sure you are in the project root directory:

    port-scanner/

### Interactive Mode

    python3 -m port_scanner.cli --interactive

### Professional CLI Mode

Scan single host:

    python3 -m port_scanner.cli 127.0.0.1 --ports 1-1024 --threads 300 --timeout 0.4 --lang en

Scan CIDR range:

    python3 -m port_scanner.cli 192.168.1.0/24 --ports 22,80,443,445 --lang en

Banner grabbing:

    python3 -m port_scanner.cli 127.0.0.1 --ports 80,443 --banner

Open ports only:

    python3 -m port_scanner.cli 127.0.0.1 --open-only

Disable banner:

    python3 -m port_scanner.cli 127.0.0.1 --no-banner

Export open ports to TXT:

    python3 -m port_scanner.cli 127.0.0.1 --out-txt open_ports.txt

Export full results to CSV:

    python3 -m port_scanner.cli 127.0.0.1 --out-csv scan.csv

Print version:

    python3 -m port_scanner.cli --version


## Example Output

    [OPEN] 127.0.0.1:22 (ssh)
    [OPEN] 127.0.0.1:80 (http)

    Summary: open 2/1024 | threads=300 | timeout=0.4s | elapsed=1.32s

## Running Tests (Optional)

    pytest

## License

This project is licensed under the MIT License.

## Author

Onur Keskin\
Cybersecurity & OT Enthusiast
