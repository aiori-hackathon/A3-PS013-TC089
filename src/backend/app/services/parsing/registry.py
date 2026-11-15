"""Parser registry for built-in formats and pluggable log parsers."""

from typing import Dict, Iterable, Optional, Tuple

from app.services.parsing.apache_parser import ApacheParser
from app.services.parsing.base_parser import BaseParser
from app.services.parsing.csv_parser import CSVParser
from app.services.parsing.generic_parser import GenericParser
from app.services.parsing.json_parser import JSONParser
from app.services.parsing.syslog_parser import SyslogParser


class ParserRegistry:
    """Maps detected format names to parser instances and optional aliases."""

    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._aliases: Dict[str, str] = {}

    def register(
        self,
        name: str,
        parser: BaseParser,
        aliases: Iterable[str] = (),
    ) -> BaseParser:
        key = name.strip().lower()
        if not key:
            raise ValueError("Parser format name cannot be empty.")
        self._parsers[key] = parser
        self._aliases[key] = key
        for alias in aliases:
            alias_key = alias.strip().lower()
            if alias_key:
                self._aliases[alias_key] = key
        return parser

    def get(self, name: Optional[str], default: str = "generic") -> BaseParser:
        key = (name or "").strip().lower()
        resolved = self._aliases.get(key, key)
        parser = self._parsers.get(resolved)
        if parser is not None:
            return parser
        fallback = self._parsers.get(default)
        if fallback is None:
            raise KeyError(f"No parser registered for format '{name}'.")
        return fallback

    def formats(self) -> Tuple[str, ...]:
        return tuple(sorted(self._parsers))


parser_registry = ParserRegistry()
parser_registry.register("json", JSONParser(), aliases=("jsonl", "ndjson"))
parser_registry.register("csv", CSVParser(), aliases=("delimited",))
parser_registry.register("syslog", SyslogParser(), aliases=("auth", "authlog"))
parser_registry.register("apache", ApacheParser(), aliases=("httpd", "access", "error"))
parser_registry.register(
    "generic",
    GenericParser(),
    aliases=("cef", "leef", "logfmt", "keyvalue", "kv", "unknown", ""),
)


def register_parser(
    name: str,
    parser: BaseParser,
    aliases: Iterable[str] = (),
) -> BaseParser:
    """Register a custom parser format for future ingestions."""
    return parser_registry.register(name, parser, aliases=aliases)


def get_parser(name: Optional[str]) -> BaseParser:
    """Return the parser registered for a format, falling back to generic."""
    return parser_registry.get(name)
