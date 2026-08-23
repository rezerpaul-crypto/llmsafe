"""Base protocol and helpers for scanner rules."""

from pathlib import Path
from typing import Iterable, Protocol

from llmsafe.models import Finding


class Rule(Protocol):
    """Minimal interface implemented by every scanner rule."""

    def scan(self, path: Path, content: str) -> Iterable[Finding]:
        """Return zero or more findings for *path*."""
        ...


def line_and_column(content: str, offset: int) -> tuple[int, int]:
    """Convert a character offset into one-based line and column values."""

    line = content.count("\n", 0, offset) + 1
    previous_newline = content.rfind("\n", 0, offset)
    column = offset + 1 if previous_newline == -1 else offset - previous_newline
    return line, column


def line_containing(content: str, needle: str) -> tuple[int, int]:
    """Return the first location of *needle*, falling back to the file start."""

    offset = content.find(needle)
    return line_and_column(content, max(offset, 0))
