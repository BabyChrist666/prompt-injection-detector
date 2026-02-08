"""Tests for risk scoring."""

import pytest

from prompt_injection_detector.scoring import (
    RiskLevel,
    RiskScore,
    ScoringConfig,
    RiskScorer,
)
from prompt_injection_detector.patterns import (
    PatternMatch,
    InjectionPattern,
    PatternCategory,
)
from prompt_injection_detector.heuristics import (
    HeuristicResult,
    HeuristicType,
)


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_levels_exist(self):
        assert RiskLevel.SAFE
        assert RiskLevel.LOW
        assert RiskLevel.MEDIUM
        assert RiskLevel.HIGH
        assert RiskLevel.CRITICAL

    def test_level_values(self):
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.CRITICAL.value == "critical"


class TestRiskScore:
    """Tests for RiskScore."""

    def test_create_score(self):
        score = RiskScore(
            overall_score=0.75,
            risk_level=RiskLevel.HIGH,
            pattern_score=0.8,
            heuristic_score=0.6,
        )
        assert score.overall_score == 0.75
        assert score.risk_level == RiskLevel.HIGH

    def test_to_dict(self):
        score = RiskScore(
            overall_score=0.5,
            risk_level=RiskLevel.MEDIUM,
            pattern_score=0.6,
            heuristic_score=0.3,
            flags=["test_flag"],
            recommendation="Test recommendation",
        )
        d = score.to_dict()
        assert d["overall_score"] == 0.5
        assert d["risk_level"] == "medium"
        assert "test_flag" in d["flags"]


class TestScoringConfig:
    """Tests for ScoringConfig."""

    def test_default_config(self):
        config = ScoringConfig()
        assert config.pattern_weight == 0.7
        assert config.heuristic_weight == 0.3
        assert config.low_threshold == 0.2

    def test_custom_config(self):
        config = ScoringConfig(
            pattern_weight=0.5,
            heuristic_weight=0.5,
            critical_threshold=0.9,
        )
        assert config.pattern_weight == 0.5
        assert config.critical_threshold == 0.9


def create_pattern_match(name: str, severity: float, category: PatternCategory) -> PatternMatch:
    """Helper to create a pattern match."""
    pattern = InjectionPattern(
        name=name,
        pattern=r"test",
        category=category,
        severity=severity,
    )
    return PatternMatch(
        pattern=pattern,
        matched_text="test",
        start=0,
        end=4,
    )


def create_heuristic_result(
    htype: HeuristicType,
    triggered: bool,
    score: float,
) -> HeuristicResult:
    """Helper to create a heuristic result."""
    return HeuristicResult(
        heuristic_type=htype,
        triggered=triggered,
        score=score,
    )


class TestRiskScorer:
    """Tests for RiskScorer."""

    def test_create_scorer(self):
        scorer = RiskScorer()
        assert scorer.config is not None

    def test_score_no_matches(self):
        scorer = RiskScorer()
        score = scorer.score([], [])

        assert score.overall_score == 0.0
        assert score.risk_level == RiskLevel.SAFE

    def test_score_low_severity(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("low", 0.3, PatternCategory.ENCODING_ABUSE)
        ]
        score = scorer.score(matches, [])

        assert score.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]

    def test_score_high_severity(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("jailbreak", 0.95, PatternCategory.JAILBREAK)
        ]
        score = scorer.score(matches, [])

        assert score.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_score_multiple_patterns(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("p1", 0.5, PatternCategory.INSTRUCTION_OVERRIDE),
            create_pattern_match("p2", 0.6, PatternCategory.ROLE_MANIPULATION),
            create_pattern_match("p3", 0.7, PatternCategory.JAILBREAK),
        ]
        score = scorer.score(matches, [])

        # Multiple patterns should boost score
        assert score.pattern_score > 0.5
        assert score.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_score_heuristics(self):
        scorer = RiskScorer()
        heuristics = [
            create_heuristic_result(HeuristicType.ENTROPY, True, 0.7),
            create_heuristic_result(HeuristicType.LENGTH, True, 0.5),
        ]
        score = scorer.score([], heuristics)

        assert score.heuristic_score > 0

    def test_score_combined(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("test", 0.6, PatternCategory.INSTRUCTION_OVERRIDE)
        ]
        heuristics = [
            create_heuristic_result(HeuristicType.INSTRUCTION_DENSITY, True, 0.8)
        ]
        score = scorer.score(matches, heuristics)

        assert score.pattern_score > 0
        assert score.heuristic_score > 0
        assert score.overall_score > 0

    def test_category_scores(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("p1", 0.9, PatternCategory.JAILBREAK),
            create_pattern_match("p2", 0.7, PatternCategory.INSTRUCTION_OVERRIDE),
        ]
        score = scorer.score(matches, [])

        assert "jailbreak" in score.category_scores
        assert "instruction_override" in score.category_scores
        assert score.category_scores["jailbreak"] == 0.9

    def test_flags_generated(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("critical", 0.95, PatternCategory.JAILBREAK)
        ]
        heuristics = [
            create_heuristic_result(HeuristicType.ENTROPY, True, 0.7)
        ]
        score = scorer.score(matches, heuristics)

        assert len(score.flags) > 0
        assert any("jailbreak" in f for f in score.flags)

    def test_recommendation_safe(self):
        scorer = RiskScorer()
        score = scorer.score([], [])

        assert "safe" in score.recommendation.lower()

    def test_recommendation_critical(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("jailbreak", 0.95, PatternCategory.JAILBREAK)
        ]
        score = scorer.score(matches, [])

        if score.risk_level == RiskLevel.CRITICAL:
            assert "block" in score.recommendation.lower()

    def test_risk_levels(self):
        scorer = RiskScorer()

        # Test each threshold
        config = scorer.config

        # Below low threshold
        matches = [create_pattern_match("t", 0.1, PatternCategory.ENCODING_ABUSE)]
        score = scorer.score(matches, [])
        assert score.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]

    def test_quick_score(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("test", 0.7, PatternCategory.INSTRUCTION_OVERRIDE)
        ]
        quick = scorer.quick_score(matches)

        assert quick > 0

    def test_is_safe(self):
        scorer = RiskScorer()

        safe_score = RiskScore(
            overall_score=0.1,
            risk_level=RiskLevel.SAFE,
            pattern_score=0.0,
            heuristic_score=0.1,
        )
        assert scorer.is_safe(safe_score) is True

        high_score = RiskScore(
            overall_score=0.8,
            risk_level=RiskLevel.HIGH,
            pattern_score=0.8,
            heuristic_score=0.5,
        )
        assert scorer.is_safe(high_score) is False

    def test_boost_for_critical_patterns(self):
        scorer = RiskScorer()
        matches = [
            create_pattern_match("critical", 0.95, PatternCategory.JAILBREAK)
        ]
        score = scorer.score(matches, [])

        # Score should be boosted for critical patterns
        assert score.overall_score > score.pattern_score * 0.7
