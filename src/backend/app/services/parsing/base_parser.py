"""Base parser definitions and data structures for forensic log ingestion."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


@dataclass
class ParsedRecord:
    """Standardized parsed record extracted by log parsers."""
    original_timestamp: Optional[str] = None
    source_system: Optional[str] = None
    event_type: Optional[str] = None
    event_category: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    raw_record: str = ""
    parsing_status: str = "OK"  # OK, PARTIAL, FAILED
    extra_fields: Dict[str, Any] = field(default_factory=dict)

    def evaluate_status(self):
        """Automatically evaluate whether record is OK, PARTIAL, or FAILED."""
        if not self.raw_record:
            self.parsing_status = "FAILED"
            return

        has_timestamp = bool(self.original_timestamp and str(self.original_timestamp).strip())
        has_context = bool(self.description or self.event_type or self.username or self.source_ip)

        if has_timestamp and has_context:
            self.parsing_status = "OK"
        elif has_timestamp or has_context:
            self.parsing_status = "PARTIAL"
        else:
            self.parsing_status = "FAILED"


class BaseParser(ABC):
    """Abstract base class for all forensic format parsers."""

    @abstractmethod
    def parse(self, content: str, default_source: Optional[str] = None) -> List[ParsedRecord]:
        """Parse text content into a list of standardized ParsedRecord objects."""
        pass
