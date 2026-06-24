"""File Parser - Extract text from uploaded files (PDF, DOCX, TXT, CSV, JSON)."""

import csv
import io
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def extract_text_from_file(content: bytes, filename: str) -> Optional[str]:
    """Extract text from a file based on its extension."""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

    try:
        if ext == "txt":
            return content.decode("utf-8", errors="ignore")

        elif ext == "pdf":
            return _extract_pdf(content)

        elif ext in ("doc", "docx"):
            return _extract_docx(content)

        elif ext == "csv":
            return _extract_csv(content)

        elif ext == "json":
            return _extract_json(content)

        else:
            # Try to decode as text
            return content.decode("utf-8", errors="ignore")

    except Exception as e:
        logger.error(f"Failed to parse file {filename}: {e}")
        return None


def _extract_pdf(content: bytes) -> str:
    """Extract text from PDF file."""
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(io.BytesIO(content))
        text_parts = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
        return "\n".join(text_parts)
    except ImportError:
        logger.warning("PyPDF2 not installed, cannot parse PDF")
        return None
    except Exception as e:
        logger.error(f"PDF parsing error: {e}")
        return None


def _extract_docx(content: bytes) -> str:
    """Extract text from DOCX file."""
    try:
        from docx import Document
        doc = Document(io.BytesIO(content))
        text_parts = [para.text for para in doc.paragraphs if para.text.strip()]
        return "\n".join(text_parts)
    except ImportError:
        logger.warning("python-docx not installed, cannot parse DOCX")
        return None
    except Exception as e:
        logger.error(f"DOCX parsing error: {e}")
        return None


def _extract_csv(content: bytes) -> str:
    """Extract text from CSV file."""
    text = content.decode("utf-8", errors="ignore")
    reader = csv.reader(io.StringIO(text))
    rows = [" ".join(row) for row in reader]
    return "\n".join(rows)


def _extract_json(content: bytes) -> str:
    """Extract text from JSON file."""
    text = content.decode("utf-8", errors="ignore")
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return json.dumps(data, indent=2)
        elif isinstance(data, list):
            return "\n".join([json.dumps(item) for item in data])
        return str(data)
    except json.JSONDecodeError:
        return text
