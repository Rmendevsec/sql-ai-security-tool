"""
Core API module for advanced API endpoint discovery and fuzzing.
"""

from .crawler import APICrawler as AdvancedAPICrawler
from .parser import APIResponseParser
from .fuzzer import APIFuzzer
from .auth import AuthTester
from .report import ReportGenerator

__version__ = "1.0.0"
__all__ = ['AdvancedAPICrawler', 'APIResponseParser', 'AdvancedAPIFuzzer', 
           'AuthDetector', 'AuthBypass', 'APIReportGenerator']