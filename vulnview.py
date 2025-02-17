#!/usr/bin/env python3

import argparse
import configparser
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Suppress SSL warnings (since Nessus often uses self-signed certificates)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def truncate_text(text, max_length=80):
    """Truncate text to a specified maximum length and add an ellipsis if needed."""
    return text if len(text) <= max_length else text[:max_length - 3] + "..."

def load_credentials(config_file):
    """Load Nessus credentials from the config file."""
    config = configparser.ConfigParser()
    config.read(config_file)
    try:
        url = config['Nessus']['url']
        access_key = config['Nessus']['access_key']
        secret_key = config['Nessus']['secret_key']
        return url, access_key, secret_key
    except KeyError as e:
        print(f"Error: Missing key in config file - {e}")
        exit(1)

def authenticate(url, access_key, secret_key):
    """Authenticate with Nessus and return the session headers."""
    headers = {
        'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}'
    }
    try:
        response = requests.get(f"{url}/session", headers=headers, verify=False)
        response.raise_for_status()
        return headers  # Return headers for subsequent requests
    except requests.exceptions.RequestException as e:
        print(f"Authentication failed: {e}")
        exit(1)

def list_folders(url, headers, console):
    """List all folders (projects) in Nessus using a rich table."""
    try:
        response = requests.get(f"{url}/folders", headers=headers, verify=False)
        response.raise_for_status()
        folders = response.json().get('folders', [])
        
        if folders:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID", style="dim", width=6)
            table.add_column("Name")
            
            for folder in folders:
                table.add_row(str(folder['id']), folder['name'])
            
            console.print("\nNessus Projects (Folders):")
            console.print(table)
        else:
            console.print("No projects (folders) found.")
    except requests.exceptions.RequestException as e:
        console.print(f"Failed to retrieve folders: {e}")
        exit(1)

def list_scans_in_folder(url, headers, folder_id, console):
    """List all scans in a specific folder by folder ID."""
    try:
        # Get all scans
        response = requests.get(f"{url}/scans", headers=headers, verify=False)
        response.raise_for_status()
        scans = response.json().get('scans', [])
        
        if scans:
            scan_data = [[str(scan['id']), scan['name']] for scan in scans if scan['folder_id'] == folder_id]
            if scan_data:
                table = Table(show_header=True, header_style="bold cyan")
                table.add_column("ID", style="dim", width=6)
                table.add_column("Name")
                
                for row in scan_data:
                    table.add_row(*row)
                
                console.print(f"\nScans in Project ID '{folder_id}':")
                console.print(table)
            else:
                console.print(f"No scans found in Project ID '{folder_id}'.")
        else:
            console.print("No scans found.")
    except requests.exceptions.RequestException as e:
        console.print(f"Failed to retrieve scans: {e}")
        exit(1)

def list_vulnerabilities_in_scan(url, headers, scan_id, console):
    """List all vulnerabilities in a specific scan, grouped by severity."""
    try:
        # Get scan details
        response = requests.get(f"{url}/scans/{scan_id}", headers=headers, verify=False)
        response.raise_for_status()
        scan_details = response.json()

        vulnerabilities = scan_details.get('vulnerabilities', [])
        if vulnerabilities:
            severity_map = {
                0: "Info",
                1: "Low",
                2: "Medium",
                3: "High",
                4: "Critical"
            }

            # Group vulnerabilities by severity
            grouped_vulns = {
                "Critical": [],
                "High": [],
                "Medium": [],
                "Low": [],
                "Info": []
            }

            for vuln in vulnerabilities:
                severity_level = severity_map.get(vuln['severity'], "Unknown")
                truncated_name = truncate_text(vuln['plugin_name'])
                grouped_vulns[severity_level].append(vuln)

            return grouped_vulns
        else:
            console.print(f"No vulnerabilities found in Scan ID '{scan_id}'.")
            return None
    except requests.exceptions.RequestException as e:
        console.print(f"Failed to retrieve vulnerabilities: {e}")
        exit(1)

def get_vulnerability_details(url, headers, scan_id, plugin_id):
    """Get detailed information about a specific vulnerability."""
    try:
        # Get scan details
        response = requests.get(f"{url}/scans/{scan_id}", headers=headers, verify=False)
        response.raise_for_status()
        scan_details = response.json()

        vulnerabilities = scan_details.get('vulnerabilities', [])
        hosts = scan_details.get('hosts', [])

        # Find the vulnerability details
        selected_vuln = None
        for vuln in vulnerabilities:
            if vuln['plugin_id'] == plugin_id:
                selected_vuln = vuln
                break

        if not selected_vuln:
            console.print(f"Vulnerability with Plugin ID '{plugin_id}' not found.")
            exit(1)

        # Extract description
        description = selected_vuln.get('description', "No description available.")

        # Extract affected assets
        affected_assets = []
        for host in hosts:
            host_details_response = requests.get(
                f"{url}/scans/{scan_id}/hosts/{host['host_id']}",
                headers=headers,
                verify=False
            )
            host_details = host_details_response.json()
            for item in host_details.get('vulnerabilities', []):
                if item['plugin_id'] == plugin_id:
                    affected_assets.append(host['hostname'])

        return description, affected_assets
    except requests.exceptions.RequestException as e:
        console.print(f"Failed to retrieve vulnerability details: {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Interact with Nessus projects and scans.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-l', '--list', action='store_true', help="List all projects (folders)")
    group.add_argument('-i', '--inspect', type=int, help="Inspect a specific project by ID")
    parser.add_argument('-s', '--scan', type=int, help="Specify a scan ID to list vulnerabilities")
    parser.add_argument('-critical', type=int, help="Show detailed information for a specific critical vulnerability")
    parser.add_argument('-high', type=int, help="Show detailed information for a specific high vulnerability")
    parser.add_argument('-medium', type=int, help="Show detailed information for a specific medium vulnerability")
    parser.add_argument('-low', type=int, help="Show detailed information for a specific low vulnerability")
    parser.add_argument('-info', type=int, help="Show detailed information for a specific info vulnerability")

    args = parser.parse_args()

    config_file = 'creds.conf'
    url, access_key, secret_key = load_credentials(config_file)
    headers = authenticate(url, access_key, secret_key)
    console = Console()

    if args.list:
        # List all projects (folders)
        list_folders(url, headers, console)
    elif args.inspect is not None:
        if args.scan is not None:
            # List vulnerabilities for a specific scan
            grouped_vulns = list_vulnerabilities_in_scan(url, headers, args.scan, console)

            # Handle severity-specific arguments
            if grouped_vulns is None:
                console.print(f"No vulnerabilities found in Scan ID '{args.scan}'.")
                exit(1)

            severity_args = {
                "Critical": args.critical,
                "High": args.high,
                "Medium": args.medium,
                "Low": args.low,
                "Info": args.info
            }

            # Check if any severity-specific argument is provided
            if any(severity_args.values()):
                for severity, index in severity_args.items():
                    if index is not None:
                        vulns = grouped_vulns.get(severity, [])
                        if not vulns:
                            console.print(f"No {severity.lower()} vulnerabilities found in Scan ID '{args.scan}'.")
                            exit(1)

                        if index < 1 or index > len(vulns):
                            console.print(f"Invalid {severity.lower()} vulnerability index. There are {len(vulns)} {severity.lower()} vulnerabilities.")
                            exit(1)

                        selected_vuln = vulns[index - 1]  # Convert one-based index to zero-based
                        plugin_id = selected_vuln['plugin_id']
                        description, affected_assets = get_vulnerability_details(url, headers, args.scan, plugin_id)

                        console.print(Panel.fit(
                            f"[bold]Severity:[/bold] {severity}\n"
                            f"[bold]Vulnerability Name:[/bold] {selected_vuln['plugin_name']}\n\n"
                            f"[bold]Description:[/bold] {description}\n\n"
                            f"[bold]Affected Assets:[/bold] {', '.join(affected_assets) if affected_assets else 'None'}",
                            title=f"Details for {severity} Vulnerability #{index}"
                        ))
                        break
            else:
                # If no severity-specific argument is provided, list all vulnerabilities
                for severity in ["Critical", "High", "Medium", "Low", "Info"]:
                    vulns = grouped_vulns.get(severity, [])
                    if vulns:
                        table = Table(show_header=True, header_style=f"bold {'red' if severity == 'Critical' else 'yellow' if severity == 'High' else 'green'}")
                        table.add_column("#", style="dim", width=4)
                        table.add_column("Vulnerability Name")
                        
                        for i, vuln in enumerate(vulns):
                            table.add_row(str(i + 1), vuln['plugin_name'])
                        
                        console.print(f"\n{severity} Vulnerabilities:")
                        console.print(table)
        else:
            # List scans in the specified project folder
            list_scans_in_folder(url, headers, args.inspect, console)

if __name__ == "__main__":
    main()
