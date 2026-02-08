"""
Main prompt injection detector.

High-level API combining all detection methods.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .patterns import PatternMatcher, PatternMatch, InjectionPattern, PatternCategory
from .heuristics import HeuristicAnalyzer, HeuristicResult, HeuristicConfig
from .scoring import RiskScorer, RiskScore, RiskLevel, ScoringConfig
from .sanitizer import InputSanitizer, SanitizationResult, SanitizerConfig


@dataclass
class DetectorConfig:
    """Configuration for the detector."""
    # Enable/disable components
    enable_patterns: bool = True
    enable_heuristics: bool = True
    enable_sanitization: bool = True

    # Component configs
    heuristic_config: Optional[HeuristicConfig] = None
    scoring_config: Optional[ScoringConfig] = None
    sanitizer_config: Optional[SanitizerConfig] = None

    # Detection thresholds
    block_threshold: float = 0.6
    warn_threshold: float = 0.3

    # Callbacks
    on_detection: Optional[Callable[["Detection"], None]] = None


@dataclass
class Detection:
    """Complete detection result."""
    input_text: str
    risk_score: RiskScore
    pattern_matches: List[PatternMatch] = field(default_factory=list)
    heuristic_results: List[HeuristicResult] = field(default_factory=list)
    sanitization: Optional[SanitizationResult] = None
    should_block: bool = False
    should_warn: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "input_length": len(self.input_text),
            "risk_score": self.risk_score.to_dict(),
            "pattern_matches": [m.to_dict() for m in self.pattern_matches],
            "heuristic_results": [r.to_dict() for r in self.heuristic_results],
            "sanitization": self.sanitization.to_dict() if self.sanitization else None,
            "should_block": self.should_block,
            "should_warn": self.should_warn,
            "metadata": self.metadata,
        }


class PromptInjectionDetector:
    """
    Main detector for prompt injection attacks.

    Combines pattern matching, heuristic analysis, and risk scoring
    to detect potential injection attempts.
    """

    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        patterns: Optional[List[InjectionPattern]] = None,
    ):
        self.config = config or DetectorConfig()

        # Initialize components
        self.pattern_matcher = PatternMatcher(patterns)
        self.heuristic_analyzer = HeuristicAnalyzer(self.config.heuristic_config)
        self.scorer = RiskScorer(self.config.scoring_config)
        self.sanitizer = InputSanitizer(self.config.sanitizer_config)

    def detect(self, text: str) -> Detection:
        """
        Analyze text for injection attacks.

        Args:
            text: Input text to analyze

        Returns:
            Detection result with risk assessment
        """
        # Pattern matching
        if self.config.enable_patterns:
            pattern_matches = self.pattern_matcher.match(text)
        else:
            pattern_matches = []

        # Heuristic analysis
        if self.config.enable_heuristics:
            heuristic_results = self.heuristic_analyzer.analyze(text)
        else:
            heuristic_results = []

        # Risk scoring
        risk_score = self.scorer.score(pattern_matches, heuristic_results)

        # Sanitization
        if self.config.enable_sanitization:
            sanitization = self.sanitizer.sanitize(text)
        else:
            sanitization = None

        # Determine actions
        should_block = risk_score.overall_score >= self.config.block_threshold
        should_warn = (
            risk_score.overall_score >= self.config.warn_threshold and
            not should_block
        )

        detection = Detection(
            input_text=text,
            risk_score=risk_score,
            pattern_matches=pattern_matches,
            heuristic_results=heuristic_results,
            sanitization=sanitization,
            should_block=should_block,
            should_warn=should_warn,
        )

        # Callback
        if self.config.on_detection:
            try:
                self.config.on_detection(detection)
            except Exception:
                pass

        return detection

    def is_safe(self, text: str) -> bool:
        """
        Quick check if text is safe.

        Args:
            text: Input text

        Returns:
            True if text appears safe
        """
        detection = self.detect(text)
        return not detection.should_block and not detection.should_warn

    def get_sanitized(self, text: str) -> str:
        """
        Get sanitized version of text.

        Args:
            text: Input text

        Returns:
            Sanitized text
        """
        return self.sanitizer.sanitize(text).sanitized

    def detect_and_sanitize(self, text: str) -> tuple:
        """
        Detect and return sanitized text.

        Args:
            text: Input text

        Returns:
            Tuple of (Detection, sanitized_text)
        """
        detection = self.detect(text)
        sanitized = detection.sanitization.sanitized if detection.sanitization else text
        return detection, sanitized

    def add_pattern(self, pattern: InjectionPattern) -> None:
        """Add a custom detection pattern."""
        self.pattern_matcher.add_pattern(pattern)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        return self.pattern_matcher.remove_pattern(name)

    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "pattern_count": len(self.pattern_matcher.patterns),
            "categories": list(set(
                p.category.value for p in self.pattern_matcher.patterns
            )),
            "config": {
                "block_threshold": self.config.block_threshold,
                "warn_threshold": self.config.warn_threshold,
            },
        }

    def batch_detect(self, texts: List[str]) -> List[Detection]:
        """
        Detect on multiple texts.

        Args:
            texts: List of input texts

        Returns:
            List of Detection results
        """
        return [self.detect(text) for text in texts]

    def get_high_risk(self, detections: List[Detection]) -> List[Detection]:
        """Filter detections to only high risk."""
        return [
            d for d in detections
            if d.risk_score.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        ]


def create_detector(
    strict: bool = False,
    custom_patterns: Optional[List[InjectionPattern]] = None,
) -> PromptInjectionDetector:
    """
    Create a detector with common settings.

    Args:
        strict: Use stricter thresholds
        custom_patterns: Additional patterns to include

    Returns:
        Configured PromptInjectionDetector
    """
    if strict:
        config = DetectorConfig(
            block_threshold=0.4,
            warn_threshold=0.2,
        )
    else:
        config = DetectorConfig()

    detector = PromptInjectionDetector(config, custom_patterns)
    return detector
