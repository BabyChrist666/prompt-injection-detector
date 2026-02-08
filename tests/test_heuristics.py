"""Tests for heuristic analysis."""

import pytest

from prompt_injection_detector.heuristics import (
    HeuristicType,
    HeuristicResult,
    HeuristicConfig,
    HeuristicAnalyzer,
)


class TestHeuristicType:
    """Tests for HeuristicType enum."""

    def test_types_exist(self):
        assert HeuristicType.ENTROPY
        assert HeuristicType.LENGTH
        assert HeuristicType.STRUCTURE
        assert HeuristicType.REPETITION
        assert HeuristicType.SPECIAL_CHARS
        assert HeuristicType.LANGUAGE_SWITCH
        assert HeuristicType.INSTRUCTION_DENSITY

    def test_type_values(self):
        assert HeuristicType.ENTROPY.value == "entropy"
        assert HeuristicType.LENGTH.value == "length"


class TestHeuristicResult:
    """Tests for HeuristicResult."""

    def test_create_result(self):
        result = HeuristicResult(
            heuristic_type=HeuristicType.ENTROPY,
            triggered=True,
            score=0.8,
            message="High entropy detected",
        )
        assert result.triggered is True
        assert result.score == 0.8

    def test_to_dict(self):
        result = HeuristicResult(
            heuristic_type=HeuristicType.LENGTH,
            triggered=False,
            score=0.2,
            details={"length": 100},
        )
        d = result.to_dict()
        assert d["heuristic_type"] == "length"
        assert d["triggered"] is False
        assert d["details"]["length"] == 100


class TestHeuristicConfig:
    """Tests for HeuristicConfig."""

    def test_default_config(self):
        config = HeuristicConfig()
        assert config.max_entropy == 5.5
        assert config.max_length == 10000
        assert config.max_repetition_ratio == 0.3

    def test_custom_config(self):
        config = HeuristicConfig(
            max_entropy=6.0,
            max_length=5000,
        )
        assert config.max_entropy == 6.0
        assert config.max_length == 5000


class TestHeuristicAnalyzer:
    """Tests for HeuristicAnalyzer."""

    def test_create_analyzer(self):
        analyzer = HeuristicAnalyzer()
        assert analyzer.config is not None

    def test_analyze_returns_all_types(self):
        analyzer = HeuristicAnalyzer()
        results = analyzer.analyze("Hello world")

        # Should have a result for each heuristic type
        types_found = {r.heuristic_type for r in results}
        assert HeuristicType.ENTROPY in types_found
        assert HeuristicType.LENGTH in types_found
        assert HeuristicType.STRUCTURE in types_found

    def test_check_entropy_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_entropy("Hello, this is normal English text.")

        assert result.heuristic_type == HeuristicType.ENTROPY
        assert result.triggered is False
        assert result.score < 0.3

    def test_check_entropy_high(self):
        analyzer = HeuristicAnalyzer()
        # Random characters have high entropy
        text = "aZ9!@#xYz0*&^qWe1$%rTy2"
        result = analyzer.check_entropy(text)

        # Entropy should be calculated
        assert "entropy" in result.details
        assert result.details["entropy"] > 0

    def test_check_entropy_low(self):
        analyzer = HeuristicAnalyzer()
        # Repeated single character has low entropy
        text = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        result = analyzer.check_entropy(text)

        assert result.triggered is True
        assert result.details["entropy"] < 1.0

    def test_check_entropy_empty(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_entropy("")

        assert result.triggered is False
        assert result.score == 0.0

    def test_check_length_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_length("Short text")

        assert result.triggered is False
        assert result.score == 0.0

    def test_check_length_long(self):
        analyzer = HeuristicAnalyzer()
        long_text = "x" * 12000
        result = analyzer.check_length(long_text)

        assert result.triggered is True
        assert result.score > 0

    def test_check_structure_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_structure("Normal text without special markers.")

        assert result.triggered is False

    def test_check_structure_many_markers(self):
        analyzer = HeuristicAnalyzer()
        text = "###\n---\n###\n---\n###\n---\n###"
        result = analyzer.check_structure(text)

        assert result.triggered is True
        assert "many_section_markers" in result.details.get("issues", [])

    def test_check_repetition_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_repetition("The quick brown fox jumps over the lazy dog.")

        assert result.triggered is False

    def test_check_repetition_char(self):
        analyzer = HeuristicAnalyzer()
        text = "hellooooooooooooooooo world"
        result = analyzer.check_repetition(text)

        assert result.triggered is True
        assert result.details["max_char_repeat"] > 10

    def test_check_repetition_word(self):
        analyzer = HeuristicAnalyzer()
        text = "the the the the the the the the the other words"
        result = analyzer.check_repetition(text)

        assert result.details["word_repeat_ratio"] > 0.3

    def test_check_repetition_short(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_repetition("hi")

        assert result.triggered is False
        assert "too short" in result.message.lower()

    def test_check_special_chars_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_special_chars("Hello, world!")

        assert result.triggered is False

    def test_check_special_chars_high(self):
        analyzer = HeuristicAnalyzer()
        text = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        result = analyzer.check_special_chars(text)

        assert result.triggered is True
        assert result.details["special_ratio"] > 0.5

    def test_check_special_chars_control(self):
        analyzer = HeuristicAnalyzer()
        text = "hello\x00\x01\x02world"
        result = analyzer.check_special_chars(text)

        assert result.triggered is True
        assert "control_chars" in result.details.get("issues", []) or result.details.get("control_chars", 0) > 0

    def test_check_language_switch_single(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_language_switch("Hello world in English only.")

        assert result.triggered is False

    def test_check_language_switch_multiple(self):
        analyzer = HeuristicAnalyzer()
        # Mix of Latin, Cyrillic, and CJK
        text = "Hello " + "\u0430" * 20 + " " + "\u4E00" * 20
        result = analyzer.check_language_switch(text)

        assert "scripts" in result.details
        active = sum(1 for v in result.details["scripts"].values() if v > 10)
        assert active >= 2

    def test_check_instruction_density_normal(self):
        analyzer = HeuristicAnalyzer()
        result = analyzer.check_instruction_density("The weather is nice today.")

        assert result.triggered is False
        assert result.details["density"] < 0.1

    def test_check_instruction_density_high(self):
        analyzer = HeuristicAnalyzer()
        text = "ignore forget override bypass system prompt instructions rules"
        result = analyzer.check_instruction_density(text)

        assert result.triggered is True
        assert result.details["density"] > 0.5

    def test_get_combined_score_none_triggered(self):
        analyzer = HeuristicAnalyzer()
        results = analyzer.analyze("Normal safe text here.")

        score = analyzer.get_combined_score(results)
        assert score < 0.3

    def test_get_combined_score_some_triggered(self):
        analyzer = HeuristicAnalyzer()
        # Text with issues
        text = "ignore forget override bypass " + "x" * 5000 + "!@#$%^" * 100
        results = analyzer.analyze(text)

        score = analyzer.get_combined_score(results)
        assert score > 0.2
