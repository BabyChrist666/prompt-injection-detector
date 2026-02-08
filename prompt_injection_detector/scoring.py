"""
Risk scoring for prompt injection detection.

Combines multiple signals into a unified risk assessment.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum

from .patterns import PatternMatch, PatternCategory
from .heuristics import HeuristicResult, HeuristicType


class RiskLevel(Enum):
    """Risk levels for detected content."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RiskScore:
    """Comprehensive risk assessment."""
    overall_score: float  # 0.0 to 1.0
    risk_level: RiskLevel
    pattern_score: float
    heuristic_score: float
    category_scores: Dict[str, float] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "overall_score": round(self.overall_score, 3),
            "risk_level": self.risk_level.value,
            "pattern_score": round(self.pattern_score, 3),
            "heuristic_score": round(self.heuristic_score, 3),
            "category_scores": {
                k: round(v, 3) for k, v in self.category_scores.items()
            },
            "flags": self.flags,
            "recommendation": self.recommendation,
        }


@dataclass
class ScoringConfig:
    """Configuration for risk scoring."""
    # Weight for pattern vs heuristic scores
    pattern_weight: float = 0.7
    heuristic_weight: float = 0.3

    # Risk level thresholds
    low_threshold: float = 0.2
    medium_threshold: float = 0.4
    high_threshold: float = 0.6
    critical_threshold: float = 0.8

    # Category weights
    category_weights: Dict[PatternCategory, float] = field(default_factory=lambda: {
        PatternCategory.INSTRUCTION_OVERRIDE: 1.0,
        PatternCategory.ROLE_MANIPULATION: 0.8,
        PatternCategory.CONTEXT_ESCAPE: 0.9,
        PatternCategory.DATA_EXFILTRATION: 0.85,
        PatternCategory.JAILBREAK: 1.0,
        PatternCategory.ENCODING_ABUSE: 0.6,
        PatternCategory.DELIMITER_ABUSE: 0.7,
        PatternCategory.PROMPT_LEAKING: 0.75,
    })


class RiskScorer:
    """
    Computes risk scores from pattern matches and heuristics.

    Provides a unified risk assessment for potential injection attacks.
    """

    def __init__(self, config: Optional[ScoringConfig] = None):
        self.config = config or ScoringConfig()

    def score(
        self,
        pattern_matches: List[PatternMatch],
        heuristic_results: List[HeuristicResult],
    ) -> RiskScore:
        """
        Compute risk score from detection results.

        Args:
            pattern_matches: Pattern detection results
            heuristic_results: Heuristic analysis results

        Returns:
            RiskScore with comprehensive assessment
        """
        # Calculate pattern score
        pattern_score = self._calculate_pattern_score(pattern_matches)
        category_scores = self._calculate_category_scores(pattern_matches)

        # Calculate heuristic score
        heuristic_score = self._calculate_heuristic_score(heuristic_results)

        # Combine scores
        overall_score = (
            pattern_score * self.config.pattern_weight +
            heuristic_score * self.config.heuristic_weight
        )

        # Boost for critical patterns
        if any(m.pattern.severity > 0.9 for m in pattern_matches):
            overall_score = min(1.0, overall_score * 1.3)

        # Determine risk level
        risk_level = self._determine_risk_level(overall_score)

        # Generate flags
        flags = self._generate_flags(pattern_matches, heuristic_results)

        # Generate recommendation
        recommendation = self._generate_recommendation(risk_level, flags)

        return RiskScore(
            overall_score=overall_score,
            risk_level=risk_level,
            pattern_score=pattern_score,
            heuristic_score=heuristic_score,
            category_scores=category_scores,
            flags=flags,
            recommendation=recommendation,
        )

    def _calculate_pattern_score(self, matches: List[PatternMatch]) -> float:
        """Calculate score from pattern matches."""
        if not matches:
            return 0.0

        # Use weighted combination of severities
        total_weight = 0.0
        weighted_severity = 0.0

        seen_patterns = set()
        for match in matches:
            if match.pattern.name in seen_patterns:
                continue
            seen_patterns.add(match.pattern.name)

            category_weight = self.config.category_weights.get(
                match.pattern.category, 0.5
            )
            weighted_severity += match.pattern.severity * category_weight
            total_weight += category_weight

        if total_weight > 0:
            base_score = weighted_severity / total_weight
        else:
            base_score = 0.0

        # Boost for multiple matches
        match_count_boost = min(0.3, len(seen_patterns) * 0.05)

        return min(1.0, base_score + match_count_boost)

    def _calculate_category_scores(
        self,
        matches: List[PatternMatch],
    ) -> Dict[str, float]:
        """Calculate scores per category."""
        category_max: Dict[str, float] = {}

        for match in matches:
            category = match.pattern.category.value
            current = category_max.get(category, 0.0)
            category_max[category] = max(current, match.pattern.severity)

        return category_max

    def _calculate_heuristic_score(
        self,
        results: List[HeuristicResult],
    ) -> float:
        """Calculate score from heuristic results."""
        if not results:
            return 0.0

        # Weighted average of triggered heuristics
        total_score = sum(r.score for r in results if r.triggered)
        triggered_count = sum(1 for r in results if r.triggered)

        if triggered_count == 0:
            return 0.0

        avg_score = total_score / triggered_count

        # Boost for many triggered heuristics
        count_boost = min(0.2, triggered_count * 0.04)

        return min(1.0, avg_score + count_boost)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score."""
        if score >= self.config.critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.config.high_threshold:
            return RiskLevel.HIGH
        elif score >= self.config.medium_threshold:
            return RiskLevel.MEDIUM
        elif score >= self.config.low_threshold:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE

    def _generate_flags(
        self,
        pattern_matches: List[PatternMatch],
        heuristic_results: List[HeuristicResult],
    ) -> List[str]:
        """Generate warning flags."""
        flags = []

        # Pattern-based flags
        categories_seen = set()
        for match in pattern_matches:
            categories_seen.add(match.pattern.category)

            if match.pattern.severity > 0.9:
                flags.append(f"critical_pattern:{match.pattern.name}")

        for category in categories_seen:
            flags.append(f"category:{category.value}")

        # Heuristic-based flags
        for result in heuristic_results:
            if result.triggered and result.score > 0.5:
                flags.append(f"heuristic:{result.heuristic_type.value}")

        return list(set(flags))

    def _generate_recommendation(
        self,
        risk_level: RiskLevel,
        flags: List[str],
    ) -> str:
        """Generate recommendation based on risk level."""
        if risk_level == RiskLevel.SAFE:
            return "Input appears safe for processing."

        elif risk_level == RiskLevel.LOW:
            return "Minor suspicious patterns detected. Monitor for context."

        elif risk_level == RiskLevel.MEDIUM:
            return "Potential injection attempt. Review before processing."

        elif risk_level == RiskLevel.HIGH:
            return "Likely injection attack. Block or sanitize input."

        else:  # CRITICAL
            if any("jailbreak" in f for f in flags):
                return "Critical: Jailbreak attempt detected. Block immediately."
            elif any("instruction_override" in f for f in flags):
                return "Critical: Instruction override attempt. Block input."
            else:
                return "Critical: High-confidence injection attack. Block input."

    def quick_score(self, pattern_matches: List[PatternMatch]) -> float:
        """Quick scoring using only pattern matches."""
        return self._calculate_pattern_score(pattern_matches)

    def is_safe(self, risk_score: RiskScore) -> bool:
        """Check if input is considered safe."""
        return risk_score.risk_level in [RiskLevel.SAFE, RiskLevel.LOW]
