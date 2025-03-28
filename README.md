# Elasticsearch Process Hunter

A tool for analyzing Windows process logs in Elasticsearch to identify suspicious or important processes based on keywords, and visualize their relationships in process trees.

## Features

- Search Elasticsearch logs for process events containing specified keywords (case-insensitive)
- Build process trees with parent-child relationships
- Display formatted, colored output with highlighted keyword matches
- Decode encoded PowerShell commands (-encodedcommand and Base64)
- Export results to CSV or formatted text output
- Progress tracking for long-running operations

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to an Elasticsearch instance with Windows process logs

### Setup

1. Clone this repository:
   ```bash
   git clone https://github.com/hzguendi/es-process-hunter.git
   cd es-process-hunter
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure your Elasticsearch connection in `.env`:
   ```
   ES_PROTOCOL=https
   ES_HOST=your-es-host.example.com
   ES_PORT=9200
   ES_USERNAME=your_username
   ES_PASSWORD=your_password
   ```

4. Configure your search parameters in `config.json` (see Configuration section below)

## Configuration

### Environment Variables (.env)

- `ES_PROTOCOL`: Protocol for Elasticsearch (http or https)
- `ES_HOST`: Hostname of the Elasticsearch server
- `ES_PORT`: Port number for Elasticsearch (usually 9200)
- `ES_USERNAME`: Elasticsearch username
- `ES_PASSWORD`: Elasticsearch password

### Search Configuration (config.json)

```json
{
  "search_keywords": ["powershell", "cmd.exe", "-enc", "rundll32"],
  "blacklist_keywords": ["chrome.exe", "explorer.exe", "firefox.exe"],
  "additional_fields": ["user.name", "host.name", "winlog.event_data.SubjectUserName"],
  "date_range": {
    "start": "now-7d",
    "end": "now"
  },
  "indices": [".ds-logs-system.security-*", ".ds-logs-windows.sysmon_operational-*"],
  "limit": 1000,
  "timezone": "CET",
  "output_format": {
    "tree": "text",
    "table": "text",
    "csv_path": "output.csv"
  },
  "lineage": {
    "fetch": true,
    "ancestors": true,
    "descendants": true,
    "show_in_tree": true,
    "show_in_table": false,
    "include_in_csv": true
  }
}
```

- `search_keywords`: List of keywords to search for in process details
- `blacklist_keywords`: List of keywords to exclude from direct results (processes with these keywords will be shown only if part of lineage)
- `additional_fields`: Extra fields to include in the results table
- `date_range`: Time range for the search (using Elasticsearch date syntax)
- `indices`: Elasticsearch indices to search in
- `limit`: Maximum number of results to retrieve
- `timezone`: Timezone for date displays
- `output_format`: Configuration for output formats
  - `tree`: Tree output format ("text")
  - `table`: Table output format ("text")
  - `csv_path`: Path for CSV export
  - `tree_path`: Path for process tree text export (plain text without color formatting)
  - `show_cmdline`: Whether to show command lines in process trees (default: false)
  - `show_source_port`: Whether to show source ports in process trees (default: false)
  - `show_dest_port`: Whether to show destination ports in process trees (default: false)
- `lineage`: Process lineage configuration
  - `fetch`: Whether to fetch process lineage at all (default: true)
  - `ancestors`: Include parent/ancestor processes (default: true)
  - `descendants`: Include child/descendant processes (default: true)
  - `show_in_tree`: Show lineage in process trees (default: true)
  - `show_in_table`: Show lineage in output table (default: true)
  - `include_in_csv`: Include lineage in CSV export (default: true)

## Usage

```bash
python es_process_analyzer.py [options]
```

### Command Line Options

- `-d`, `--debug`: Enable debug logging
- `-o`, `--output`: Specify output file for results
- `-f`, `--from-date`: Override start date from config (format: YYYY-MM-DD or Elasticsearch date math)
- `-t`, `--to-date`: Override end date from config (format: YYYY-MM-DD or Elasticsearch date math)
- `-k`, `--keywords`: Additional keywords to search for (comma separated)
- `-b`, `--blacklist`: Keywords to exclude from results (comma separated)
- `-l`, `--limit`: Maximum number of results to retrieve
- `-i`, `--indices`: Elasticsearch indices to search (comma separated)

**Process Lineage Options:**
- `--lineage`: Enable process lineage fetching (default: on)
- `--no-lineage`: Disable process lineage fetching (only direct matches)
- `--ancestors`: Include ancestor (parent) processes in lineage (default: on)
- `--no-ancestors`: Exclude ancestor (parent) processes from lineage
- `--descendants`: Include descendant (child) processes in lineage (default: on)
- `--no-descendants`: Exclude descendant (child) processes from lineage
- `--lineage-in-tree`: Show lineage in process trees (default: on)
- `--no-lineage-in-tree`: Don't show lineage in process trees
- `--lineage-in-table`: Show lineage in process tables (default: on)
- `--no-lineage-in-table`: Don't show lineage in process tables
- `--lineage-in-csv`: Include lineage in CSV export (default: on)
- `--no-lineage-in-csv`: Don't include lineage in CSV export

**Display Options:**
- `--show-cmdline`: Show command line for each process in the tree
- `--no-show-cmdline`: Don't show command line in the tree (default)
- `--show-source-port`: Show source port for each process in the tree if available
- `--no-show-source-port`: Don't show source port in the tree (default)
- `--show-dest-port`: Show destination port for each process in the tree if available
- `--no-show-dest-port`: Don't show destination port in the tree (default)
- `--show-ports`: Show both source and destination ports (shorthand for --show-source-port --show-dest-port)
- `--csv`: Export table to CSV with specified filename
- `--tree-out`: Export process tree to plain text file with specified filename (without color codes)
- `--list-fields`: Only list all possible fields/columns in each index without performing any search
- `--timezone`: Override timezone (default: CET)
- `-c`, `--config`: Path to configuration file (default: config.json)

### Examples

Basic search using configuration file:
```bash
python es_process_analyzer.py
```

Search for specific keywords with debug output:
```bash
python es_process_analyzer.py -d -k "mimikatz,rubeus,secretsdump"
```

Search within a specific date range and export to CSV:
```bash
python es_process_analyzer.py -f "2025-01-01" -t "2025-01-31" --csv results.csv
```

Search without including process lineage (only exact matches):
```bash
python es_process_analyzer.py --no-lineage -k "powershell,rundll32"
```

Search including only parent processes (but not child processes):
```bash
python es_process_analyzer.py --ancestors --no-descendants
```

Show lineage in the tree view but not in the table or CSV export:
```bash
python es_process_analyzer.py --lineage-in-tree --no-lineage-in-table --no-lineage-in-csv
```

Show full command lines in the process tree for better analysis:
```bash
python es_process_analyzer.py --show-cmdline -k "powershell,-enc"
```

Show network port information in the process tree for network activity analysis:
```bash
python es_process_analyzer.py --show-ports -k "svchost,dns,http"
```

Show only source ports in process trees:
```bash
python es_process_analyzer.py --show-source-port -k "netcat,powershell"
```

Search for suspicious processes while excluding common browsers:
```bash
python es_process_analyzer.py -k "cmd.exe,powershell" -b "chrome.exe,firefox.exe,msedge.exe"
```

Export process trees to a text file for later analysis:
```bash
python es_process_analyzer.py --tree-out output/analysis.txt -k "svchost,powershell,rundll32" --show-ports
```

Search in specific indices:
```bash
python es_process_analyzer.py -i ".ds-logs-windows.sysmon_operational-*"
```

List all possible fields/columns in each index without performing any search:
```bash
python es_process_analyzer.py --list-fields -i ".ds-logs-windows.sysmon_operational-*"
```

## Compatibility and Use Cases

The Elasticsearch Process Hunter is designed to work with the following data sources:

### Compatible Data Sources

- **Windows Security Event Logs** (`.ds-logs-system.security-*` indices)
- **Sysmon Logs** (`.ds-logs-windows.sysmon_operational-*` indices)

### Threat Hunting & Incident Response Applications

This tool is particularly valuable for threat hunting and incident response across various stages of the Cyber Kill Chain and MITRE ATT&CK framework:

- **Initial Access & Execution Detection**: Identify unusual process execution patterns that may indicate initial compromise
- **Privilege Escalation Analysis**: Track process lineage to detect when low-privilege processes spawn high-privilege children
- **Defense Evasion Techniques**: Automatically decode obfuscated PowerShell commands (-EncodedCommand flags)
- **Credential Access**: Find processes associated with credential dumping tools and techniques
- **Discovery Activities**: Detect reconnaissance activities through command-line analysis
- **Lateral Movement Tracing**: Follow process chains that indicate movement between systems
- **Command & Control Communication**: Identify suspicious network connections from processes
- **Exfiltration Attempts**: Detect unusual data handling processes and their relationships

### Pyramid of Pain Applications

The tool helps analysts tackle various levels of the Pyramid of Pain:

- **Hash Values**: Track specific process hash values of known malicious files
- **IP Addresses**: Correlate process activities with suspicious network connections
- **Domain Names**: Link processes to suspicious DNS queries (when using Sysmon DNS events)
- **Host Artifacts**: Identify suspicious process execution patterns, file paths, and Registry modifications
- **Tools**: Detect living-off-the-land binaries (LOLBins) and common attack tools through command-line analysis
- **TTPs**: Visualize complex process trees to understand advanced persistent threat (APT) tactics and techniques

### Real-World Applications

- **SOC Daily Operations**: Quickly investigate alerts related to suspicious process execution
- **Incident Response**: Reconstruct process execution timelines during security incidents
- **Threat Hunting**: Proactively search for indicators of compromise in process execution history
- **Forensic Analysis**: Build comprehensive process trees to understand the full scope of an attack
- **APT Detection**: Identify sophisticated threat actors using the process relationship analysis
- **Compliance Monitoring**: Track privileged user activities and administrative actions

## Output

The script produces two main outputs:

1. **Process Trees**: Visual representation of process hierarchies with parent-child relationships, with matching processes highlighted
2. **Process Table**: Detailed tabular view of all processes with their properties, decoded commands, and network information

Both outputs highlight matches to make suspicious activities more visible.

## Notes

- PowerShell encoded commands are automatically decoded when detected
- Command-line options override configuration file settings
- The script uses batching and scrolling to handle large result sets efficiently
