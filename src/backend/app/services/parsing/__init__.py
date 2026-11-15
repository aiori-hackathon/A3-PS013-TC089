"""Forensic log parsers package."""

from app.services.parsing.apache_parser import ApacheParser
from app.services.parsing.base_parser import BaseParser, ParsedRecord
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.generic_parser import GenericParser, is_generic_line
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.registry import (
    ParserRegistry,
    get_parser,
    parser_registry,
    register_parser,
)
from app.services.parsing.syslog_parser import SyslogParser

__all__ = [
    "ApacheParser",
    "BaseParser",
    "ParsedRecord",
    "CSVParser",
    "GenericParser",
    "JSONParser",
    "ParserRegistry",
    "SyslogParser",
    "get_parser",
    "is_generic_line",
    "parser_registry",
    "register_parser",
]
