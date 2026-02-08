"""
Input sanitization for prompt injection prevention.

Provides methods to clean and sanitize potentially malicious input.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import re
import html


@dataclass
class SanitizationResult:
    """Result of input sanitization."""
    original: str
    sanitized: str
    changes_made: List[str] = field(default_factory=list)
    removed_count: int = 0
    modified: bool = False

    def to_dict(self) -> dict:
        return {
            "original_length": len(self.original),
            "sanitized_length": len(self.sanitized),
            "changes_made": self.changes_made,
            "removed_count": self.removed_count,
            "modified": self.modified,
        }


@dataclass
class SanitizerConfig:
    """Configuration for input sanitization."""
    # Content limits
    max_length: int = 10000
    truncate_on_overflow: bool = True

    # Character handling
    strip_control_chars: bool = True
    strip_invisible_unicode: bool = True
    normalize_whitespace: bool = True

    # Delimiter handling
    escape_delimiters: bool = True
    delimiter_escape_char: str = "\\"

    # HTML/XML handling
    escape_html: bool = False
    strip_html_tags: bool = True

    # Encoding handling
    decode_html_entities: bool = True
    strip_unicode_homoglyphs: bool = True

    # Custom replacements
    custom_replacements: Dict[str, str] = field(default_factory=dict)


class InputSanitizer:
    """
    Sanitizes user input to prevent injection attacks.

    Provides various methods to clean and normalize input.
    """

    def __init__(self, config: Optional[SanitizerConfig] = None):
        self.config = config or SanitizerConfig()

        # Dangerous delimiters to escape
        self.dangerous_delimiters = [
            "[INST]", "[/INST]",
            "[SYS]", "[/SYS]",
            "<<SYS>>", "<</SYS>>",
            "<|im_start|>", "<|im_end|>",
            "<|system|>", "<|user|>", "<|assistant|>",
            "###", "---",
            "<system>", "</system>",
        ]

        # Invisible unicode ranges
        self.invisible_ranges = [
            (0x200B, 0x200F),  # Zero-width chars
            (0x2028, 0x202F),  # Line/paragraph separators
            (0x2060, 0x206F),  # Word joiner, invisible times
            (0xFEFF, 0xFEFF),  # BOM
        ]

        # Homoglyph mappings (common lookalikes)
        self.homoglyphs = {
            '\u0430': 'a',  # Cyrillic a
            '\u0435': 'e',  # Cyrillic e
            '\u043e': 'o',  # Cyrillic o
            '\u0440': 'p',  # Cyrillic r
            '\u0441': 'c',  # Cyrillic c
            '\u0445': 'x',  # Cyrillic x
            '\u0443': 'y',  # Cyrillic y
            '\u0456': 'i',  # Ukrainian i
        }

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Apply all configured sanitization steps.

        Args:
            text: Input text to sanitize

        Returns:
            SanitizationResult with sanitized text and details
        """
        original = text
        changes = []
        removed_count = 0

        # Length check
        if len(text) > self.config.max_length:
            if self.config.truncate_on_overflow:
                text = text[:self.config.max_length]
                changes.append(f"truncated_to_{self.config.max_length}")
                removed_count += len(original) - len(text)

        # Control characters
        if self.config.strip_control_chars:
            new_text, count = self._strip_control_chars(text)
            if count > 0:
                text = new_text
                changes.append(f"removed_{count}_control_chars")
                removed_count += count

        # Invisible unicode
        if self.config.strip_invisible_unicode:
            new_text, count = self._strip_invisible_unicode(text)
            if count > 0:
                text = new_text
                changes.append(f"removed_{count}_invisible_chars")
                removed_count += count

        # Homoglyphs
        if self.config.strip_unicode_homoglyphs:
            new_text, count = self._normalize_homoglyphs(text)
            if count > 0:
                text = new_text
                changes.append(f"normalized_{count}_homoglyphs")

        # HTML entities
        if self.config.decode_html_entities:
            new_text = html.unescape(text)
            if new_text != text:
                text = new_text
                changes.append("decoded_html_entities")

        # HTML tags
        if self.config.strip_html_tags:
            new_text = self._strip_html_tags(text)
            if new_text != text:
                changes.append("stripped_html_tags")
                removed_count += len(text) - len(new_text)
                text = new_text

        # Escape HTML
        if self.config.escape_html:
            new_text = html.escape(text)
            if new_text != text:
                text = new_text
                changes.append("escaped_html")

        # Whitespace normalization
        if self.config.normalize_whitespace:
            new_text = self._normalize_whitespace(text)
            if new_text != text:
                text = new_text
                changes.append("normalized_whitespace")

        # Dangerous delimiters
        if self.config.escape_delimiters:
            new_text, count = self._escape_delimiters(text)
            if count > 0:
                text = new_text
                changes.append(f"escaped_{count}_delimiters")

        # Custom replacements
        for pattern, replacement in self.config.custom_replacements.items():
            if pattern in text:
                text = text.replace(pattern, replacement)
                changes.append(f"replaced_{pattern}")

        return SanitizationResult(
            original=original,
            sanitized=text,
            changes_made=changes,
            removed_count=removed_count,
            modified=original != text,
        )

    def _strip_control_chars(self, text: str) -> Tuple[str, int]:
        """Remove control characters."""
        result = []
        removed = 0
        for char in text:
            code = ord(char)
            if code < 32 and char not in '\n\r\t':
                removed += 1
            else:
                result.append(char)
        return ''.join(result), removed

    def _strip_invisible_unicode(self, text: str) -> Tuple[str, int]:
        """Remove invisible unicode characters."""
        result = []
        removed = 0
        for char in text:
            code = ord(char)
            is_invisible = any(
                start <= code <= end
                for start, end in self.invisible_ranges
            )
            if is_invisible:
                removed += 1
            else:
                result.append(char)
        return ''.join(result), removed

    def _normalize_homoglyphs(self, text: str) -> Tuple[str, int]:
        """Replace homoglyphs with ASCII equivalents."""
        result = []
        normalized = 0
        for char in text:
            if char in self.homoglyphs:
                result.append(self.homoglyphs[char])
                normalized += 1
            else:
                result.append(char)
        return ''.join(result), normalized

    def _strip_html_tags(self, text: str) -> str:
        """Remove HTML tags."""
        return re.sub(r'<[^>]+>', '', text)

    def _normalize_whitespace(self, text: str) -> str:
        """Normalize whitespace."""
        # Replace multiple spaces with single space
        text = re.sub(r'[ \t]+', ' ', text)
        # Replace multiple newlines with double newline
        text = re.sub(r'\n{3,}', '\n\n', text)
        return text.strip()

    def _escape_delimiters(self, text: str) -> Tuple[str, int]:
        """Escape dangerous delimiters."""
        escaped = 0
        for delimiter in self.dangerous_delimiters:
            if delimiter in text:
                escaped_delimiter = ''.join(
                    f"{self.config.delimiter_escape_char}{c}" if c in '[]<>|'
                    else c
                    for c in delimiter
                )
                count = text.count(delimiter)
                text = text.replace(delimiter, escaped_delimiter)
                escaped += count
        return text, escaped

    def quick_clean(self, text: str) -> str:
        """
        Quick cleaning with minimal sanitization.

        Args:
            text: Input text

        Returns:
            Cleaned text
        """
        # Just strip control chars and normalize whitespace
        text, _ = self._strip_control_chars(text)
        text = self._normalize_whitespace(text)
        return text

    def validate_length(self, text: str) -> bool:
        """Check if text is within length limits."""
        return len(text) <= self.config.max_length

    def add_custom_replacement(self, pattern: str, replacement: str) -> None:
        """Add a custom replacement rule."""
        self.config.custom_replacements[pattern] = replacement

    def add_homoglyph(self, char: str, replacement: str) -> None:
        """Add a custom homoglyph mapping."""
        self.homoglyphs[char] = replacement
