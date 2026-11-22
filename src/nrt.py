
#!/usr/bin/env python3

"""
Network Reconnaissance Toolkit (NRT)

A Python-based network reconnaissance automation tool.

Authorized private lab networks and loopback only.
"""

import argparse
import csv
import ipaddress
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

from datetime import datetime, timezone
from pathlib import Path


# ---------------- CONFIGURATION ----------------

BASE_DIR = Path(__file__).resolve().parent.parent

SCAN_DIR = BASE_DIR / "reports" / "scans"
JSON_DIR = BASE_DIR / "reports" / "json"
CSV_DIR = BASE_DIR / "reports" / "csv"

MAX_HOSTS = 256
SCAN_TIMEOUT = 300

ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


# ---------------- DIRECTORY SETUP ----------------

def setup_directories():
    for directory in (SCAN_DIR, JSON_DIR, CSV_DIR):
        directory.mkdir(parents=True, exist_ok=True)


# ---------------- TARGET VALIDATION ----------------

def validate_target(target):

    try:
        network = ipaddress.ip_network(target, strict=False)

    except ValueError:
        raise ValueError("Invalid IPv4 address or CIDR network.")

    if network.version != 4:
        raise ValueError("Only IPv4 targets are supported.")

    if network.num_addresses > MAX_HOSTS:
        raise ValueError(
            f"Network exceeds the maximum of {MAX_HOSTS} addresses."
        )

    permitted = any(
        network.subnet_of(allowed)
        for allowed in ALLOWED_NETWORKS
    )

    if not permitted:
        raise ValueError(
            "Target must be inside an approved private or loopback network."
        )

    return str(network)


# ---------------- PORT VALIDATION ----------------

def validate_ports(ports):

    import re

    if not re.fullmatch(r"[0-9,-]+", ports):
        raise ValueError("Invalid port specification.")

    for item in ports.split(","):

        if not item:
            raise ValueError("Empty port entry.")

        if "-" in item:

            parts = item.split("-")

            if len(parts) != 2:
                raise ValueError("Invalid port range.")

            start, end = map(int, parts)

            if not (1 <= start <= end <= 65535):
                raise ValueError(
                    "Port range must be between 1 and 65535."
                )

        else:

            port = int(item)

            if not 1 <= port <= 65535:
                raise ValueError(
                    "Port must be between 1 and 65535."
                )

    return ports


# ---------------- NMAP EXECUTION ----------------

def run_nmap(target, ports, service_detection, skip_ping):

    nmap_path = shutil.which("nmap")

    if not nmap_path:
        raise RuntimeError("Nmap is not installed or not in PATH.")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    xml_file = SCAN_DIR / f"scan_{timestamp}.xml"

    command = [
        nmap_path,
        "-n",
        "-sT",
        "-T3",
        "--reason",
        "-p", ports,
        "-oX", str(xml_file),
    ]

    if service_detection:
        command.extend(["-sV", "--version-light"])

    if skip_ping:
        command.append("-Pn")

    command.append(target)

    print("\n[+] Starting Nmap reconnaissance")
    print("[+] Target:", target)
    print("[+] Ports:", ports)
    print("[+] Executing scan...\n")

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Scan exceeded the configured timeout."
        )

    if result.returncode != 0:

        raise RuntimeError(
            "Nmap execution failed:\n" + result.stderr
        )

    if not xml_file.exists() or xml_file.stat().st_size == 0:
        raise RuntimeError(
            "Nmap did not produce a valid XML output."
        )

    print("[+] Nmap scan completed.")

    return xml_file


# ---------------- XML PARSING ----------------

def parse_nmap_xml(xml_file):

    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []

    for host in root.findall("host"):

        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        address_element = host.find(
            "address[@addrtype='ipv4']"
        )

        if address_element is None:
            continue

        host_ip = address_element.get("addr")

        hostname_element = host.find(
            "hostnames/hostname"
        )

        hostname = (
            hostname_element.get("name")
            if hostname_element is not None
            else "Unknown"
        )

        ports = []

        for port in host.findall("ports/port"):

            state_element = port.find("state")

            if state_element is None:
                continue

            service_element = port.find("service")

            service_name = (
                service_element.get("name", "unknown")
                if service_element is not None
                else "unknown"
            )

            service_version = (
                service_element.get("version", "")
                if service_element is not None
                else ""
            )

            product = (
                service_element.get("product", "")
                if service_element is not None
                else ""
            )

            ports.append({

                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": state_element.get("state"),
                "service": service_name,
                "product": product,
                "version": service_version,

            })

        hosts.append({

            "ip": host_ip,
            "hostname": hostname,
            "ports": ports,

        })

    return hosts


# ---------------- REPORT GENERATION ----------------

def generate_reports(target, hosts, xml_file):

    timestamp = datetime.now(timezone.utc).isoformat()

    scan_id = xml_file.stem

    total_hosts = len(hosts)

    total_open_ports = sum(
        1
        for host in hosts
        for port in host["ports"]
        if port["state"] == "open"
    )

    report = {

        "project": "Network Reconnaissance Toolkit",
        "scan_id": scan_id,
        "timestamp_utc": timestamp,
        "target": target,
        "total_live_hosts": total_hosts,
        "total_open_ports": total_open_ports,
        "hosts": hosts,

    }

    json_file = JSON_DIR / f"{scan_id}.json"

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    csv_file = CSV_DIR / f"{scan_id}.csv"

    with csv_file.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        fieldnames = [
            "ip",
            "hostname",
            "port",
            "protocol",
            "state",
            "service",
            "product",
            "version",
        ]

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for host in hosts:

            for port in host["ports"]:

                writer.writerow({
                    "ip": host["ip"],
                    "hostname": host["hostname"],
                    **port,
                })

    return report, json_file, csv_file


# ---------------- SUMMARY ----------------

def display_summary(report, json_file, csv_file, xml_file):

    print("\n" + "=" * 55)

    print("       NETWORK RECONNAISSANCE TOOLKIT")

    print("=" * 55)

    print("Target:", report["target"])

    print("Live Hosts:", report["total_live_hosts"])

    print("Open Ports:", report["total_open_ports"])

    print("-" * 55)

    for host in report["hosts"]:

        print("\nHost:", host["ip"])

        print("Hostname:", host["hostname"])

        for port in host["ports"]:

            if port["state"] == "open":

                print(
                    f"  {port['port']}/{port['protocol']} "
                    f"{port['service']} "
                    f"{port['product']} "
                    f"{port['version']}"
                )

    print("\n[+] JSON report:", json_file)

    print("[+] CSV report:", csv_file)

    print("[+] XML report:", xml_file)

    print("=" * 55)


# ---------------- MAIN ----------------

def main():

    parser = argparse.ArgumentParser(
        description="Network Reconnaissance Toolkit"
    )

    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Authorized private IPv4 address or CIDR"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Ports to scan. Default: 1-1000"
    )

    parser.add_argument(
        "--service",
        action="store_true",
        help="Enable service and version detection"
    )

    parser.add_argument(
        "--skip-ping",
        action="store_true",
        help="Scan selected hosts without host discovery"
    )

    args = parser.parse_args()

    try:

        target = validate_target(args.target)

        ports = validate_ports(args.ports)

        setup_directories()

        xml_file = run_nmap(
            target,
            ports,
            args.service,
            args.skip_ping
        )

        hosts = parse_nmap_xml(xml_file)

        report, json_file, csv_file = generate_reports(
            target,
            hosts,
            xml_file
        )

        display_summary(
            report,
            json_file,
            csv_file,
            xml_file
        )

    except (
        ValueError,
        RuntimeError,
        ET.ParseError,
        OSError
    ) as error:

        print("\n[ERROR]", error, file=sys.stderr)

        sys.exit(1)


if __name__ == "__main__":
    main()

