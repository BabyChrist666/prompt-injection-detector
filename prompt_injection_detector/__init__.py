"""
Prompt Injection Detector: Real-time Detection of Prompt Injection Attacks

A security toolkit for detecting and preventing prompt injection attacks
in LLM applications.
"""

from .detector import PromptInjectionDetector, DetectorConfig, Detection
from .patterns import PatternMatcher, InjectionPattern, PatternCategory
from .heuristics import HeuristicAnalyzer, HeuristicResult, HeuristicType
from .scoring import RiskScorer, RiskScore, RiskLevel
from .sanitizer import InputSanitizer, SanitizationResult

__version__ = "0.1.0"

__all__ = [
    "PromptInjectionDetector",
    "DetectorConfig",
    "Detection",
    "PatternMatcher",
    "InjectionPattern",
    "PatternCategory",
    "HeuristicAnalyzer",
    "HeuristicResult",
    "HeuristicType",
    "RiskScorer",
    "RiskScore",
    "RiskLevel",
    "InputSanitizer",
    "SanitizationResult",
]
