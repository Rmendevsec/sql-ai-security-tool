#!/usr/bin/env python3
"""
Main entry point for the API Hacking Tool
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from interface.cli import main_cli
from interface.webui.app import run_webui

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--webui':
        run_webui()
    else:
        main_cli()

if __name__ == "__main__":
    main()