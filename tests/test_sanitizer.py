"""Tests for input sanitization."""

import pytest

from prompt_injection_detector.sanitizer import (
    SanitizationResult,
    SanitizerConfig,
    InputSanitizer,
)


class TestSanitizationResult:
    """Tests for SanitizationResult."""

    def test_create_result(self):
        result = SanitizationResult(
            original="hello",
            sanitized="hello",
            modified=False,
        )
        assert result.original == "hello"
        assert result.sanitized == "hello"
        assert result.modified is False

    def test_to_dict(self):
        result = SanitizationResult(
            original="hello\x00world",
            sanitized="helloworld",
            changes_made=["removed_1_control_chars"],
            removed_count=1,
            modified=True,
        )
        d = result.to_dict()
        assert d["original_length"] == 11
        assert d["sanitized_length"] == 10
        assert d["modified"] is True


class TestSanitizerConfig:
    """Tests for SanitizerConfig."""

    def test_default_config(self):
        config = SanitizerConfig()
        assert config.max_length == 10000
        assert config.strip_control_chars is True
        assert config.escape_delimiters is True

    def test_custom_config(self):
        config = SanitizerConfig(
            max_length=5000,
            strip_control_chars=False,
        )
        assert config.max_length == 5000
        assert config.strip_control_chars is False


class TestInputSanitizer:
    """Tests for InputSanitizer."""

    def test_create_sanitizer(self):
        sanitizer = InputSanitizer()
        assert sanitizer.config is not None

    def test_sanitize_normal_text(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("Hello, world!")

        assert result.sanitized == "Hello, world!"
        assert result.modified is False

    def test_sanitize_control_chars(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello\x00\x01\x02world")

        assert "\x00" not in result.sanitized
        assert "\x01" not in result.sanitized
        assert result.modified is True
        assert result.removed_count > 0

    def test_sanitize_preserves_newlines(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello\nworld\ttab")

        # Newlines preserved, tabs may be normalized to spaces
        assert "\n" in result.sanitized
        assert "world" in result.sanitized
        assert "tab" in result.sanitized

    def test_sanitize_invisible_unicode(self):
        sanitizer = InputSanitizer()
        # Zero-width space
        result = sanitizer.sanitize("hello\u200bworld")

        assert "\u200b" not in result.sanitized
        assert result.modified is True

    def test_sanitize_homoglyphs(self):
        sanitizer = InputSanitizer()
        # Cyrillic 'a' looks like Latin 'a'
        result = sanitizer.sanitize("hello \u0430 world")

        assert "\u0430" not in result.sanitized
        assert "a" in result.sanitized

    def test_sanitize_html_tags(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello <script>alert('xss')</script> world")

        assert "<script>" not in result.sanitized
        assert "</script>" not in result.sanitized
        assert result.modified is True

    def test_sanitize_html_entities(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello &amp; world")

        assert "&" in result.sanitized
        assert "&amp;" not in result.sanitized

    def test_sanitize_whitespace(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello    world\n\n\n\n\ntest")

        assert "    " not in result.sanitized
        assert "\n\n\n" not in result.sanitized

    def test_sanitize_delimiters(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello [INST] dangerous [/INST] world")

        # Delimiters should be escaped
        assert "[INST]" not in result.sanitized
        assert result.modified is True

    def test_sanitize_length_limit(self):
        config = SanitizerConfig(max_length=100)
        sanitizer = InputSanitizer(config)
        long_text = "x" * 200
        result = sanitizer.sanitize(long_text)

        assert len(result.sanitized) <= 100
        assert result.modified is True

    def test_sanitize_custom_replacements(self):
        config = SanitizerConfig(
            custom_replacements={"badword": "[removed]"}
        )
        sanitizer = InputSanitizer(config)
        result = sanitizer.sanitize("hello badword world")

        assert "badword" not in result.sanitized
        assert "[removed]" in result.sanitized

    def test_quick_clean(self):
        sanitizer = InputSanitizer()
        result = sanitizer.quick_clean("hello\x00   world   \n\n\ntest")

        assert "\x00" not in result
        assert "   " not in result

    def test_validate_length(self):
        sanitizer = InputSanitizer()

        assert sanitizer.validate_length("short") is True
        assert sanitizer.validate_length("x" * 20000) is False

    def test_add_custom_replacement(self):
        sanitizer = InputSanitizer()
        sanitizer.add_custom_replacement("secret", "[redacted]")

        result = sanitizer.sanitize("the secret password")
        assert "secret" not in result.sanitized
        assert "[redacted]" in result.sanitized

    def test_add_homoglyph(self):
        sanitizer = InputSanitizer()
        sanitizer.add_homoglyph("\u0435", "e")  # Cyrillic e

        result = sanitizer.sanitize("h\u0435llo")
        assert "\u0435" not in result.sanitized
        assert "hello" in result.sanitized

    def test_escape_html_option(self):
        config = SanitizerConfig(escape_html=True, strip_html_tags=False)
        sanitizer = InputSanitizer(config)
        result = sanitizer.sanitize("hello <b>world</b>")

        assert "&lt;b&gt;" in result.sanitized

    def test_multiple_sanitizations(self):
        sanitizer = InputSanitizer()

        # Text with multiple issues
        text = "hello\x00 [INST] <script> \u200b   world"
        result = sanitizer.sanitize(text)

        assert "\x00" not in result.sanitized
        assert "[INST]" not in result.sanitized
        assert "<script>" not in result.sanitized
        assert "\u200b" not in result.sanitized
        assert len(result.changes_made) > 0

    def test_changes_made_tracked(self):
        sanitizer = InputSanitizer()
        result = sanitizer.sanitize("hello\x00 [INST] world")

        assert len(result.changes_made) > 0
        assert any("control" in c for c in result.changes_made)
        assert any("delimiter" in c for c in result.changes_made)
