# nespar
nespar is a powerful command‑line Nessus vulnerability parser that processes CSV exports to quickly extract IPs, severities, ports, and affected hosts with an interactive menu system.

## Installation
```bash
git clone https://github.com/buraksuu/nespar.git
cd nespar
chmod +x nespar.sh
sudo cp nespar.sh /usr/local/bin/nespar
```

## Workflow
1. Run vulnerability scans with Nessus
2. Export scan results as CSV files
3. Process and analyze results with nespar

## Requirements
- Bash 4.0+
- Nessus CSV export files in the current directory

## Quick Start
```bash
# First, process your CSV files
nespar run

# Start interactive menu
nespar menu

# Show vulnerability statistics
nespar analyze
```

## Usage
```bash
nespar --help
```

### Commands
- `run` - Process CSV files and create vulnerability database
- `menu` - Start interactive menu system
- `analyze` - Show vulnerability statistics and risk assessment

### Search by vulnerability name
```bash
nespar -n "SNMP Agent Default Community Name (public)" --exclude-port
nespar --name "Microsoft Windows SMB NULL Session Authentication"
```

### Search by port
```bash
nespar -p 443
nespar -p 22 --exclude-port -o results.txt
nespar --port 80 -o web_servers.txt
```

### Filter by severity
```bash
nespar -s Critical
nespar -s High -o high.txt
nespar --severity Info
```

### Search for terms
```bash
nespar -f "apache"
nespar -f "ssl" -o ssl.txt
```

### Output options
```bash
# Save results to file
nespar -p 443 -o output.txt

# Show IPs only (without ports)
nespar -n "SSH Weak Encryption" --exclude-port
```

## Interactive Features
The interactive menu (`nespar menu`) provides:
- Browse vulnerabilities by severity level
- Browse all vulnerabilities with color-coded severity
- Search by specific port numbers
- Search by vulnerability terms
- View detailed analysis reports
- Save results to files

## File Outputs
After running `nespar run`, the following files are created:
- `scan_results_hosts_ports.txt` - Main vulnerability database with ports
- `nessus-hosts.txt` - Nessus host IP addresses

## Examples
```bash
# Process CSV files first
nespar run

# Interactive browsing
nespar menu

# Quick analysis
nespar analyze

# Find all critical vulnerabilities
nespar --severity Critical

# Find hosts with SSH service
nespar --port 22

# Search for SSL/TLS issues
nespar --find "ssl"

# Get IPs affected by specific vulnerability
nespar --name "Python Unsupported Version Detection" --exclude-port

# Save high severity issues to file
nespar --severity High --output high.txt
```


## License
The code in this project is licensed under MIT license.
