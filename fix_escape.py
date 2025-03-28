#!/usr/bin/env python3
"""
Script to fix escape sequences in the es_process_analyzer.py file
"""

import re

# Path to the file
file_path = "/Users/hzguendi/Downloads/playground/claude-auto/es-process-analyzer/es_process_analyzer.py"

# Read the file content
with open(file_path, 'r') as f:
    content = f.read()

# Fix all occurrences of \g<0> (invalid escape sequence) to \\g<0> (valid escape sequence)
fixed_content = re.sub(r'\\g<0>', r'\\\\g<0>', content)

# Write the fixed content back to the file
with open(file_path, 'w') as f:
    f.write(fixed_content)

print("Fixed all escape sequences in the file.")
