# Nessus Vulnerability Management Tool

This Python-based tool interacts with the Nessus API to manage and inspect vulnerabilities in your projects and scans. It provides a user-friendly interface to list projects, scans, and vulnerabilities, as well as retrieve detailed information about specific vulnerabilities.

### Features

- List Projects : View all available Nessus projects (folders).
- Inspect Scans : List all scans within a specific project folder.
- List Vulnerabilities : Group and display vulnerabilities by severity (Critical, High, Medium, Low, Info).
- Detailed Vulnerability Information : Retrieve detailed information (description, affected assets) for a specific vulnerability.
- Rich Output : Use rich library for visually appealing tables and panels.

### Requirements

- Python 3.8 or higher
- Nessus API credentials (Access Key and Secret Key)
- A Nessus server URL
- pip installed to install required dependencies

### Installation

- Clone the repository:

```bash
git clone https://github.com/0xhnl/vulnview.git
cd vulnview
pip3 install rich requests configparser
```

### Configuration 

- Create a creds.conf file in the root directory of the project with the following structure:

```bash
[Nessus]
url = https://<your-nessus-server>:8834
access_key = <your-access-key>
secret_key = <your-secret-key>
```

### Usage

- Run the script using Python 3. The tool supports the following commands:

```bash
➜  vulnview python3 vulnview.py 
usage: final.py [-h] (-l | -i INSPECT) [-s SCAN] [-critical CRITICAL] [-high HIGH] [-medium MEDIUM] [-low LOW]
                [-info INFO]
final.py: error: one of the arguments -l/--list -i/--inspect is required
```

- List the projects:

```bash
➜  vulnview python3 vulnview.py -l

Nessus Projects (Folders):
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID     ┃ Name                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ 1      │ project1             │
│ 2      │ project2             │
└────────┴──────────────────────┘
```

- Inspect Scans in a Specific Project:

```bash
➜  vulnview python3 vulnview.py -i 22

Scans in Project ID '22':
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ ID     ┃ Name                 ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ 01     │ Scan-01              │
│ 002    │ Scan-02              │
└────────┴──────────────────────┘
```

- List Vulnerabilities in a Specific Scan:

```bash
vulnview python3 vulnview.py -i 22 -s 34
```

- Get Details for the 13th Medium Vulnerability (only description + affected assets)

```bash
➜  vulnview python3 vulnview.py -i 22 -s 34 -medium 1
╭──────────── Details for Medium Vulnerability #1 ────────────╮
│ Severity: Medium                                            │
│ Vulnerability Name: SMTP Server Non-standard Port Detection │
│                                                             │
│ Description: No description available.                      │
│                                                             │
│ Affected Assets: 123.123.123.1                              │
╰─────────────────────────────────────────────────────────────╯
```

### Acknowledgments

- Thanks to the Nessus API Documentation for providing the necessary endpoints.
- Special thanks to the Rich Library for enabling beautiful console output.
