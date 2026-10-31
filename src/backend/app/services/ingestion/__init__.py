"""Ingestion service package."""

from app.services.ingestion.ingestor import IngestionService, detect_file_format

__all__ = ["IngestionService", "detect_file_format"]
