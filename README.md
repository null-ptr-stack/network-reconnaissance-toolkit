

# Network Reconnaissance Toolkit (NRT)

A Python and Bash-based network reconnaissance toolkit
powered by Nmap.

Automates authorized network discovery, TCP port scanning,
service identification, XML parsing, and security report
generation.

## Features

- Private IPv4 and CIDR target validation
- Network reconnaissance using Nmap
- TCP connect scanning
- Service and version detection
- Configurable port scanning
- XML scan result processing
- Automated JSON report generation
- CSV report generation
- Bash execution wrapper
- Input validation and error handling

## Technology Stack

- Kali Linux
- Python 3
- Bash
- Nmap
- XML
- JSON
- CSV
- Git

## Architecture

User Input
    |
Python CLI
    |
Target Validation
    |
Nmap Scanning Engine
    |
XML Output
    |
Python XML Parser
    |
JSON and CSV Reports

## Installation

Clone the repository:

    git clone https://github.com/null-ptr-stack/network-reconnaissance-toolkit.git

Navigate into the project:

    cd network-reconnaissance-toolkit

Install Nmap:

    sudo apt install nmap python3

Make the Bash wrapper executable:

    chmod +x scripts/run.sh

## Usage

Basic scan:

    bash scripts/run.sh -t 192.168.72.139

Service detection:

    bash scripts/run.sh -t 192.168.72.139 --service

Custom port scan:

    bash scripts/run.sh -t 192.168.72.139 -p 22,80,443

Subnet scan:

    bash scripts/run.sh -t 192.168.72.0/24 --service

Skip host discovery:

    bash scripts/run.sh -t 192.168.72.139 --skip-ping

## Output

The toolkit generates:

- Nmap XML reports
- JSON reconnaissance reports
- CSV scan summaries

Reports are stored in the reports directory.

## Testing

Run automated unit tests:

    python3 -m unittest discover -s tests -v

## Screenshots

### 1. Network Scanning
![Network Scanning](screenshots/network%20scanning%20screenshot.png)

### 2. Ping IP
![Ping IP](screenshots/ping%20IP%20screenshot.png)

### 3. Skip Ping IP
![Skip Ping IP](screenshots/skip%20ping%20ip%20screenshot.png)

### 4. Terminal Execution
![Terminal Execution](screenshots/terminal%20screenshot.png)

## Security and Scope
This toolkit is designed for authorized security testing.

The initial version restricts targets to:
- RFC1918 private IPv4 networks
- Loopback networks

It also limits a scan to 256 IP addresses.

Only scan systems that you own or have explicit
authorization to assess.

## Limitations

- IPv4 only
- TCP connect scans only
- No automatic vulnerability confirmation
- No exploit functionality
- Service identification depends on Nmap fingerprints
- Results may vary depending on firewall rules and
  network configuration

## Future Improvements

- HTML report generation
- Risk classification
- Network topology visualization
- Scan history database
- Configurable authorized-target allowlists
- Scheduled reconnaissance
- Additional network monitoring features

## Author

Sayan Kundu

Cybersecurity Student | Network Security |
Penetration Testing

## License

MIT License
