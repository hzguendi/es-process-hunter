# Elasticsearch Process Analyzer

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
   git clone https://github.com/yourusername/es-process-analyzer.git
   cd es-process-analyzer
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
  }
}
```

- `search_keywords`: List of keywords to search for in process details
- `additional_fields`: Extra fields to include in the results table
- `date_range`: Time range for the search (using Elasticsearch date syntax)
- `indices`: Elasticsearch indices to search in
- `limit`: Maximum number of results to retrieve
- `timezone`: Timezone for date displays
- `output_format`: Configuration for output formats

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
- `-l`, `--limit`: Maximum number of results to retrieve
- `-i`, `--indices`: Elasticsearch indices to search (comma separated)
- `--csv`: Export table to CSV with specified filename
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

Search in specific indices:
```bash
python es_process_analyzer.py -i ".ds-logs-windows.sysmon_operational-*"
```

## Output

The script produces two main outputs:

1. **Process Trees**: Visual representation of process hierarchies with parent-child relationships, with matching processes highlighted
2. **Process Table**: Detailed tabular view of all processes with their properties, decoded commands, and network information

Both outputs highlight matches to make suspicious activities more visible.

## Notes

- PowerShell encoded commands are automatically decoded when detected
- Command-line options override configuration file settings
- The script uses batching and scrolling to handle large result sets efficiently