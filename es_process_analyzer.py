#!/usr/bin/env python3
"""
Elasticsearch Process Analyzer

A tool to search Elasticsearch for process events matching keywords,
build process trees, and output formatted results with highlighted matches.
"""

import os
import sys
import json
import base64
import argparse
import logging
import datetime

# Script version
__version__ = "1.0.0"
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import re

import tqdm
import colorama
from colorama import Fore, Style, Back
from elasticsearch import Elasticsearch
# Import general exceptions from elasticsearch
from elasticsearch import ApiError, TransportError, ConnectionError as ESConnectionError
from dotenv import load_dotenv
import pandas as pd
from tabulate import tabulate

# Initialize colorama for cross-platform color support
colorama.init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("es-process-analyzer")

@dataclass
class Process:
    """Class to represent a process with its properties and relationships."""
    pid: int
    name: str
    command_line: str
    executable: str
    timestamp: datetime.datetime
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    parent_executable: Optional[str] = None
    additional_fields: Dict[str, Any] = field(default_factory=dict)
    children: List['Process'] = field(default_factory=list)
    matches: List[str] = field(default_factory=list)
    decoded_command: Optional[str] = None
    source_log: Dict[str, Any] = field(default_factory=dict)
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None

@dataclass
class Config:
    """Configuration for the ES process analyzer."""
    search_keywords: List[str]
    additional_fields: List[str]
    date_range: Dict[str, str]
    indices: List[str]
    limit: int
    timezone: str
    output_format: Dict[str, str]

class ESProcessAnalyzer:
    """Main class for analyzing processes in Elasticsearch logs."""
    
    def __init__(self, config_path: str, debug: bool = False):
        """Initialize the analyzer with configuration."""
        self.load_env()
        self.load_config(config_path)
        self.setup_logging(debug)
        self.connect_to_elasticsearch()
        self.processes = {}  # pid -> Process
        self.process_trees = []  # List of root processes
        
    def load_env(self) -> None:
        """Load environment variables from .env file."""
        load_dotenv()
        self.es_protocol = os.getenv("ES_PROTOCOL", "https")
        self.es_host = os.getenv("ES_HOST", "localhost")
        self.es_port = os.getenv("ES_PORT", "9200")
        self.es_username = os.getenv("ES_USERNAME")
        self.es_password = os.getenv("ES_PASSWORD")
        
        if not all([self.es_host, self.es_port, self.es_username, self.es_password]):
            logger.error("Missing required environment variables. Check .env file.")
            sys.exit(1)
            
    def load_config(self, config_path: str) -> None:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                
            self.config = Config(
                search_keywords=config_data.get("search_keywords", []),
                additional_fields=config_data.get("additional_fields", []),
                date_range=config_data.get("date_range", {"start": "now-7d", "end": "now"}),
                indices=config_data.get("indices", [".ds-logs-system.security-*"]),
                limit=config_data.get("limit", 1000),
                timezone=config_data.get("timezone", "CET"),
                output_format=config_data.get("output_format", {"tree": "text", "table": "text"})
            )
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)
            
    def setup_logging(self, debug: bool) -> None:
        """Configure logging level."""
        if debug:
            logger.setLevel(logging.DEBUG)
            logging.getLogger("elasticsearch").setLevel(logging.DEBUG)
        else:
            logging.getLogger("elasticsearch").setLevel(logging.WARNING)
            
    def connect_to_elasticsearch(self) -> None:
        """Establish connection to Elasticsearch."""
        try:
            self.es = Elasticsearch(
                [f"{self.es_protocol}://{self.es_host}:{self.es_port}"],
                basic_auth=(self.es_username, self.es_password),
                verify_certs=False if self.es_protocol == "https" else None,
                timeout=60
            )
            if not self.es.ping():
                raise ESConnectionError("Failed to connect to Elasticsearch")
            logger.info(f"Connected to Elasticsearch at {self.es_host}:{self.es_port}")
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            sys.exit(1)
            
    def search_logs(self, override_args=None) -> List[Dict]:
        """
        Search Elasticsearch for process events matching keywords.
        Returns list of matching documents.
        """
        # Apply overrides from command line arguments
        if override_args:
            if override_args.from_date:
                self.config.date_range["start"] = override_args.from_date
            if override_args.to_date:
                self.config.date_range["end"] = override_args.to_date
            if override_args.keywords:
                self.config.search_keywords.extend(override_args.keywords.split(','))
            if override_args.limit:
                self.config.limit = override_args.limit
            if override_args.indices:
                self.config.indices = override_args.indices.split(',')
            if override_args.timezone:
                self.config.timezone = override_args.timezone
        
        # Remove duplicates from keywords
        self.config.search_keywords = list(set(self.config.search_keywords))
        
        # Build query
        should_clauses = []
        for keyword in self.config.search_keywords:
            should_clauses.append({"wildcard": {"process.command_line": {"value": f"*{keyword}*", "case_insensitive": True}}})
            should_clauses.append({"wildcard": {"process.name": {"value": f"*{keyword}*", "case_insensitive": True}}})
            should_clauses.append({"wildcard": {"process.executable": {"value": f"*{keyword}*", "case_insensitive": True}}})
            
        query = {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": self.config.date_range["start"], "lte": self.config.date_range["end"]}}},
                    {"exists": {"field": "process.pid"}},
                    {"bool": {"should": should_clauses, "minimum_should_match": 1}}
                ]
            }
        }
        
        logger.debug(f"ES Query: {json.dumps(query, indent=2)}")
        
        # Execute search with scrolling for large result sets
        results = []
        total_hits = 0
        
        try:
            # Initial search
            resp = self.es.search(
                index=self.config.indices,
                query=query,
                size=1000,  # Batch size for scrolling
                sort=["@timestamp"],
                _source_includes=["@timestamp", "process.*", "event.*", "user.*", "host.*", "winlog.*", "source.*", "destination.*"] + self.config.additional_fields
            )
            
            total_hits = resp["hits"]["total"]["value"]
            logger.info(f"Found {total_hits} matching events")
            
            # Process initial results
            results.extend(resp["hits"]["hits"])
            
            # Initialize progress bar
            with tqdm.tqdm(total=min(total_hits, self.config.limit), desc="Searching logs") as pbar:
                pbar.update(len(resp["hits"]["hits"]))
                
                # Continue with scroll API for remaining results
                scroll_id = resp.get("_scroll_id")
                scroll_size = len(resp["hits"]["hits"])
                
                while scroll_size > 0 and len(results) < self.config.limit:
                    page = self.es.scroll(scroll_id=scroll_id, scroll="2m")
                    scroll_id = page["_scroll_id"]
                    scroll_size = len(page["hits"]["hits"])
                    results.extend(page["hits"]["hits"])
                    pbar.update(min(scroll_size, self.config.limit - pbar.n))
                    
                    if len(results) >= self.config.limit:
                        logger.info(f"Reached limit of {self.config.limit} results")
                        break
                        
            # Clear scroll when done
            if scroll_id:
                self.es.clear_scroll(scroll_id=scroll_id)
                
        except (ApiError, TransportError, ESConnectionError) as e:
            logger.error(f"Error searching Elasticsearch: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error during Elasticsearch search: {e}")
            sys.exit(1)
            
        logger.info(f"Retrieved {len(results)} log entries")
        return results
    
    def build_processes(self, logs: List[Dict]) -> None:
        """
        Process log entries to build process objects.
        """
        logger.info("Building process objects from logs")
        with tqdm.tqdm(total=len(logs), desc="Building processes") as pbar:
            for log in logs:
                source = log["_source"]
                
                # Skip if not a process event
                if "process" not in source:
                    pbar.update(1)
                    continue
                
                # Extract process details
                pid = source["process"].get("pid")
                name = source["process"].get("name", "")
                command_line = source["process"].get("command_line", "")
                executable = source["process"].get("executable", "")
                timestamp = datetime.datetime.fromisoformat(source["@timestamp"].replace("Z", "+00:00"))
                
                # Extract parent process details, if available
                parent_pid = None
                parent_name = None
                parent_executable = None
                if "parent" in source["process"]:
                    parent_pid = source["process"]["parent"].get("pid")
                    parent_name = source["process"]["parent"].get("name", "")
                    parent_executable = source["process"]["parent"].get("executable", "")
                
                # Skip if no pid (should not happen)
                if pid is None:
                    pbar.update(1)
                    continue
                
                # Check if this process matches any keywords
                matches = []
                for keyword in self.config.search_keywords:
                    keyword_lower = keyword.lower()
                    if (command_line and keyword_lower in command_line.lower()) or \
                       (name and keyword_lower in name.lower()) or \
                       (executable and keyword_lower in executable.lower()):
                        matches.append(keyword)
                
                # Extract network information if available
                source_ip = None
                dest_ip = None
                source_port = None
                dest_port = None
                
                if "source" in source and "ip" in source["source"]:
                    source_ip = source["source"]["ip"]
                if "source" in source and "port" in source["source"]:
                    source_port = source["source"]["port"]
                if "destination" in source and "ip" in source["destination"]:
                    dest_ip = source["destination"]["ip"]
                if "destination" in source and "port" in source["destination"]:
                    dest_port = source["destination"]["port"]
                
                # Get event type
                event_type = None
                if "event" in source:
                    if "code" in source["event"]:
                        event_type = source["event"]["code"]
                    elif "type" in source["event"]:
                        event_type = ','.join(source["event"]["type"]) if isinstance(source["event"]["type"], list) else source["event"]["type"]
                
                # Extract additional fields
                additional_fields = {}
                for field in self.config.additional_fields:
                    field_parts = field.split(".")
                    value = source
                    for part in field_parts:
                        if part in value:
                            value = value[part]
                        else:
                            value = None
                            break
                    if value is not None:
                        additional_fields[field] = value
                
                # Create or update process object
                if pid in self.processes:
                    # Update existing process with new information
                    process = self.processes[pid]
                    process.name = name if name and not process.name else process.name
                    process.command_line = command_line if command_line and not process.command_line else process.command_line
                    process.executable = executable if executable and not process.executable else process.executable
                    process.parent_pid = parent_pid if parent_pid is not None else process.parent_pid
                    process.parent_name = parent_name if parent_name and not process.parent_name else process.parent_name
                    process.parent_executable = parent_executable if parent_executable and not process.parent_executable else process.parent_executable
                    
                    # Update network info
                    process.source_ip = source_ip if source_ip else process.source_ip
                    process.dest_ip = dest_ip if dest_ip else process.dest_ip
                    process.source_port = source_port if source_port else process.source_port
                    process.dest_port = dest_port if dest_port else process.dest_port
                    
                    # Update event type
                    process.event_type = event_type if event_type else process.event_type
                    
                    # Add additional fields
                    for key, value in additional_fields.items():
                        if key not in process.additional_fields or not process.additional_fields[key]:
                            process.additional_fields[key] = value
                    
                    # Add matches if not already present
                    for match in matches:
                        if match not in process.matches:
                            process.matches.append(match)
                else:
                    # Create new process
                    process = Process(
                        pid=pid,
                        name=name,
                        command_line=command_line,
                        executable=executable,
                        timestamp=timestamp,
                        parent_pid=parent_pid,
                        parent_name=parent_name,
                        parent_executable=parent_executable,
                        additional_fields=additional_fields,
                        matches=matches,
                        source_log=source,
                        event_type=event_type,
                        source_ip=source_ip,
                        dest_ip=dest_ip,
                        source_port=source_port,
                        dest_port=dest_port
                    )
                    self.processes[pid] = process
                
                # Decode encoded PowerShell commands
                if command_line and ("-enc" in command_line.lower() or "-encodedcommand" in command_line.lower()):
                    process.decoded_command = self.decode_powershell_command(command_line)
                
                pbar.update(1)
    
    def build_process_trees(self) -> None:
        """
        Build process trees based on parent-child relationships.
        """
        logger.info("Building process trees")
        
        # First, add children to their parent processes
        with tqdm.tqdm(total=len(self.processes), desc="Building parent-child relationships") as pbar:
            for pid, process in self.processes.items():
                if process.parent_pid and process.parent_pid in self.processes:
                    parent = self.processes[process.parent_pid]
                    parent.children.append(process)
                pbar.update(1)
        
        # Find root processes (those without a parent in our dataset)
        self.process_trees = []
        for pid, process in self.processes.items():
            if not process.parent_pid or process.parent_pid not in self.processes:
                self.process_trees.append(process)
        
        logger.info(f"Built {len(self.process_trees)} process trees")
    
    def decode_powershell_command(self, command_line: str) -> Optional[str]:
        """
        Decode PowerShell encoded commands.
        """
        # Look for encoded command in the command line
        encoded_patterns = [
            r'(?:-enc(?:odedCommand)?)\s+([A-Za-z0-9+/=]+)',
            r'(?:-e(?:nc)?)\s+([A-Za-z0-9+/=]+)'
        ]
        
        for pattern in encoded_patterns:
            match = re.search(pattern, command_line, re.IGNORECASE)
            if match:
                encoded_text = match.group(1)
                try:
                    # Base64 decode then decode as UTF-16LE (PowerShell standard)
                    decoded_bytes = base64.b64decode(encoded_text)
                    decoded_text = decoded_bytes.decode('utf-16-le')
                    return decoded_text
                except Exception as e:
                    logger.debug(f"Failed to decode command: {e}")
                    return None
        
        return None
    
    def display_process_tree(self, root_process: Process, indent: str = "", is_last: bool = True, highlight_keywords: bool = True) -> str:
        """
        Generate a text representation of a process tree.
        Returns the formatted tree as a string.
        """
        # Sort children by timestamp
        children = sorted(root_process.children, key=lambda p: p.timestamp)
        
        # Determine the branch character
        branch = "└── " if is_last else "├── "
        
        # Format the current process node
        process_info = f"{root_process.name} (PID: {root_process.pid}, Time: {root_process.timestamp.strftime('%Y-%m-%d %H:%M:%S')})"
        
        # Highlight if process matches any keywords
        if highlight_keywords and root_process.matches:
            process_info = f"{Fore.RED}{process_info}{Style.RESET_ALL}"
            process_info += f" {Fore.YELLOW}[Matches: {', '.join(root_process.matches)}]{Style.RESET_ALL}"
        
        # Build the tree line
        tree_line = indent + branch + process_info
        
        # Generate child nodes
        child_indent = indent + ("    " if is_last else "│   ")
        
        # Process children (all but the last)
        child_lines = []
        for i, child in enumerate(children[:-1]):
            child_lines.append(self.display_process_tree(child, child_indent, False, highlight_keywords))
        
        # Process the last child if any
        if children:
            child_lines.append(self.display_process_tree(children[-1], child_indent, True, highlight_keywords))
        
        # Combine the lines
        return "\n".join([tree_line] + child_lines)
    
    def generate_process_table(self, highlight_keywords: bool = True) -> pd.DataFrame:
        """
        Generate a table of processes with their details.
        Returns a pandas DataFrame.
        """
        # Flatten the process tree into a list of all processes
        all_processes = list(self.processes.values())
        
        # Sort by timestamp
        all_processes.sort(key=lambda p: p.timestamp)
        
        # Create a list of dictionaries for the table
        table_data = []
        for process in all_processes:
            row = {
                "Timestamp": process.timestamp,
                "PID": process.pid,
                "Process Name": process.name,
                "Command Line": process.command_line,
                "Parent PID": process.parent_pid,
                "Parent Name": process.parent_name,
                "Event Code": process.event_type,
                "Source IP": process.source_ip,
                "Source Port": process.source_port,
                "Dest IP": process.dest_ip,
                "Dest Port": process.dest_port,
                "Matches": ", ".join(process.matches) if process.matches else "",
                "Decoded Command": process.decoded_command if process.decoded_command else ""
            }
            
            # Add additional fields
            for field, value in process.additional_fields.items():
                # Skip fields we already have
                if field in row:
                    continue
                row[field] = value
            
            table_data.append(row)
        
        # Create DataFrame
        df = pd.DataFrame(table_data)
        
        return df
    
    def display_process_table(self, table: pd.DataFrame, highlight_keywords: bool = True) -> str:
        """
        Display the process table with formatting.
        Returns the formatted table as a string.
        """
        # Create a copy of the DataFrame for display modifications
        display_df = table.copy()
        
        # Format timestamps
        if "Timestamp" in display_df.columns:
            display_df["Timestamp"] = display_df["Timestamp"].dt.strftime('%Y-%m-%d %H:%M:%S')
        
        # Function to highlight matched keywords in a string
        def highlight_text(text, keywords):
            if not isinstance(text, str) or not keywords:
                return text
            
            for keyword in keywords:
                if not keyword:
                    continue
                
                pattern = re.compile(re.escape(keyword), re.IGNORECASE)
                text = pattern.sub(f"{Back.YELLOW}{Fore.BLACK}\\g<0>{Style.RESET_ALL}", text)
            
            return text
        
        # Check if we need to highlight matches
        if highlight_keywords:
            # Apply highlighting to each row
            for i, row in display_df.iterrows():
                if row["Matches"]:
                    keywords = row["Matches"].split(", ")
                    
                    # Highlight matched fields
                    for col in ["Process Name", "Command Line"]:
                        if col in row and isinstance(row[col], str):
                            display_df.at[i, col] = highlight_text(row[col], keywords)
                    
                    # Highlight the matches column itself
                    display_df.at[i, "Matches"] = f"{Fore.RED}{row['Matches']}{Style.RESET_ALL}"
                    
                    # Highlight decoded command if available
                    if "Decoded Command" in row and row["Decoded Command"]:
                        display_df.at[i, "Decoded Command"] = highlight_text(row["Decoded Command"], keywords)
        
        # Convert to formatted table
        table_str = tabulate(display_df, headers='keys', tablefmt='grid', showindex=False)
        
        return table_str
    
    def export_to_csv(self, df: pd.DataFrame, output_path: str) -> None:
        """
        Export the process table to a CSV file.
        """
        try:
            df.to_csv(output_path, index=False)
            logger.info(f"Exported results to {output_path}")
        except Exception as e:
            logger.error(f"Failed to export to CSV: {e}")
    
    def run(self, args=None) -> None:
        """
        Run the full analysis workflow.
        """
        logger.info("Starting Elasticsearch process analysis")
        
        # Search for logs
        logs = self.search_logs(args)
        
        # Build process objects
        self.build_processes(logs)
        
        # Build process trees
        self.build_process_trees()
        
        # Display process trees
        print("\n" + "="*80)
        print(f"{Fore.CYAN}PROCESS TREES{Style.RESET_ALL}")
        print("="*80 + "\n")
        
        for i, root_process in enumerate(self.process_trees):
            if i > 0:
                print("\n" + "-"*80 + "\n")
            print(self.display_process_tree(root_process))
        
        # Generate and display process table
        table = self.generate_process_table()
        
        print("\n\n" + "="*80)
        print(f"{Fore.CYAN}PROCESS DETAILS{Style.RESET_ALL}")
        print("="*80 + "\n")
        
        print(self.display_process_table(table))
        
        # Export to CSV if requested
        output_file = args.output if args and args.output else self.config.output_format.get("csv_path")
        if args and args.csv:
            output_file = args.csv
            
        if output_file:
            self.export_to_csv(table, output_file)
            print(f"\n{Fore.GREEN}Results exported to {output_file}{Style.RESET_ALL}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description=f"Elasticsearch Process Analyzer v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic search using configuration file
  %(prog)s
  
  # Search for specific keywords with debug output
  %(prog)s -d -k "mimikatz,rubeus,secretsdump"
  
  # Search within a specific date range and export to CSV
  %(prog)s -f "2025-01-01" -t "2025-01-31" --csv results.csv
  
  # Search in specific indices
  %(prog)s -i ".ds-logs-windows.sysmon_operational-*"
  
  # Override config limit and add additional keywords
  %(prog)s -l 500 -k "powershell,-enc,rundll32.exe" -o output.txt
'''
    )
    
    # Add version argument
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    # Create argument groups for better organization
    config_group = parser.add_argument_group('Configuration Options')
    search_group = parser.add_argument_group('Search Options')
    output_group = parser.add_argument_group('Output Options')
    
    # Configuration options
    config_group.add_argument("-c", "--config", default="config.json", 
                          help="Path to configuration file (default: config.json)")
    config_group.add_argument("-d", "--debug", action="store_true", 
                           help="Enable debug logging for detailed output")
    config_group.add_argument("--timezone", 
                           help="Timezone for date display (default: CET from config)")
    
    # Search options
    search_group.add_argument("-k", "--keywords", 
                           help="Additional search keywords (comma separated)")
    search_group.add_argument("-f", "--from-date", 
                           help="Start date (YYYY-MM-DD or Elasticsearch date math like 'now-7d')")
    search_group.add_argument("-t", "--to-date", 
                           help="End date (YYYY-MM-DD or Elasticsearch date math like 'now')")
    search_group.add_argument("-l", "--limit", type=int, 
                           help="Maximum number of results to retrieve")
    search_group.add_argument("-i", "--indices", 
                           help="Elasticsearch indices to search (comma separated)")
    
    # Output options
    output_group.add_argument("-o", "--output", 
                           help="Output file path for formatted text results")
    output_group.add_argument("--csv", 
                           help="Export table to CSV with specified filename")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    args = parse_args()
    analyzer = ESProcessAnalyzer(args.config, args.debug)
    analyzer.run(args)

if __name__ == "__main__":
    main()