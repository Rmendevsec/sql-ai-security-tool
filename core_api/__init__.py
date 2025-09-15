"""
Core API module for advanced API endpoint discovery and fuzzing.
"""

from .crawler import AdvancedAPICrawler
from .parser import APIResponseParser
from .fuzzer import AdvancedAPIFuzzer
from .auth import AuthDetector, AuthBypass
from .report import APIReportGenerator

__version__ = "1.0.0"
__all__ = ['AdvancedAPICrawler', 'APIResponseParser', 'AdvancedAPIFuzzer', 
           'AuthDetector', 'AuthBypass', 'APIReportGenerator']