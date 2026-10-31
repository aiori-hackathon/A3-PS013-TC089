"""Cryptographic hashing service for digital forensic evidence verification."""

import hashlib
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 hash of a file by reading its bytes in chunks."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def calculate_sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 hash directly from byte content."""
    return hashlib.sha256(data).hexdigest()
