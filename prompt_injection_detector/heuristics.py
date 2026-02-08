"""
Heuristic analysis for prompt injection detection.

Non-pattern-based detection methods.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import re
import math


class HeuristicType(Enum):
    """Types of heuristic checks."""
    ENTROPY = "entropy"
    LENGTH = "length"
    STRUCTURE = "structure"
    REPETITION = "repetition"
    SPECIAL_CHARS = "special_chars"
    LANGUAGE_SWITCH = "language_switch"
    INSTRUCTION_DENSITY = "instruction_density"


@dataclass
class HeuristicResult:
    """Result of a heuristic check."""
    heuristic_type: HeuristicType
    triggered: bool
    score: float  # 0.0 to 1.0
    details: Dict[str, Any] = field(default_factory=dict)
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "heuristic_type": self.heuristic_type.value,
            "triggered": self.triggered,
            "score": self.score,
            "details": self.details,
            "message": self.message,
        }


@dataclass
class HeuristicConfig:
    """Configuration for heuristic analysis."""
    # Entropy thresholds
    max_entropy: float = 5.5
    min_entropy: float = 1.0

    # Length thresholds
    max_length: int = 10000
    suspicious_length: int = 5000

    # Repetition thresholds
    max_repetition_ratio: float = 0.3

    # Special character thresholds
    max_special_char_ratio: float = 0.2

    # Instruction density
    instruction_word_weight: float = 0.5

    # Weights for combining heuristics
    weights: Dict[HeuristicType, float] = field(default_factory=lambda: {
        HeuristicType.ENTROPY: 0.15,
        HeuristicType.LENGTH: 0.1,
        HeuristicType.STRUCTURE: 0.2,
        HeuristicType.REPETITION: 0.15,
        HeuristicType.SPECIAL_CHARS: 0.15,
        HeuristicType.LANGUAGE_SWITCH: 0.1,
        HeuristicType.INSTRUCTION_DENSITY: 0.15,
    })


class HeuristicAnalyzer:
    """
    Analyzes text using heuristic methods.

    Provides non-pattern-based detection of suspicious content.
    """

    def __init__(self, config: Optional[HeuristicConfig] = None):
        self.config = config or HeuristicConfig()

        # Instruction-related words
        self.instruction_words = {
            "ignore", "forget", "disregard", "override", "bypass",
            "pretend", "imagine", "act", "roleplay", "behave",
            "system", "prompt", "instruction", "rule", "guideline",
            "reveal", "show", "display", "output", "print",
            "jailbreak", "developer", "unrestricted", "unfiltered",
            "assistant", "ai", "bot", "model", "gpt", "claude",
        }

    def analyze(self, text: str) -> List[HeuristicResult]:
        """
        Run all heuristic checks on text.

        Args:
            text: Text to analyze

        Returns:
            List of HeuristicResult objects
        """
        results = [
            self.check_entropy(text),
            self.check_length(text),
            self.check_structure(text),
            self.check_repetition(text),
            self.check_special_chars(text),
            self.check_language_switch(text),
            self.check_instruction_density(text),
        ]
        return results

    def check_entropy(self, text: str) -> HeuristicResult:
        """Check text entropy for anomalies."""
        if not text:
            return HeuristicResult(
                heuristic_type=HeuristicType.ENTROPY,
                triggered=False,
                score=0.0,
                message="Empty text",
            )

        # Calculate character entropy
        char_counts: Dict[str, int] = {}
        for char in text.lower():
            char_counts[char] = char_counts.get(char, 0) + 1

        total = len(text)
        entropy = 0.0
        for count in char_counts.values():
            prob = count / total
            if prob > 0:
                entropy -= prob * math.log2(prob)

        # Check for abnormal entropy
        triggered = entropy > self.config.max_entropy or entropy < self.config.min_entropy

        # Score based on how far from normal range
        if entropy > self.config.max_entropy:
            score = min(1.0, (entropy - self.config.max_entropy) / 2.0)
        elif entropy < self.config.min_entropy:
            score = min(1.0, (self.config.min_entropy - entropy) / 1.0)
        else:
            score = 0.0

        return HeuristicResult(
            heuristic_type=HeuristicType.ENTROPY,
            triggered=triggered,
            score=score,
            details={"entropy": entropy},
            message=f"Entropy: {entropy:.2f}",
        )

    def check_length(self, text: str) -> HeuristicResult:
        """Check text length for anomalies."""
        length = len(text)

        if length > self.config.max_length:
            triggered = True
            score = min(1.0, (length - self.config.max_length) / self.config.max_length)
        elif length > self.config.suspicious_length:
            triggered = True
            score = (length - self.config.suspicious_length) / (
                self.config.max_length - self.config.suspicious_length
            ) * 0.5
        else:
            triggered = False
            score = 0.0

        return HeuristicResult(
            heuristic_type=HeuristicType.LENGTH,
            triggered=triggered,
            score=score,
            details={"length": length},
            message=f"Length: {length} chars",
        )

    def check_structure(self, text: str) -> HeuristicResult:
        """Check for unusual structural patterns."""
        issues = []
        score = 0.0

        # Check for multiple instruction-like sections
        section_markers = re.findall(
            r"(###|---|\n\n\n+|={3,}|\*{3,})",
            text
        )
        if len(section_markers) > 5:
            issues.append("many_section_markers")
            score += 0.3

        # Check for unusual nesting
        bracket_depth = 0
        max_depth = 0
        for char in text:
            if char in "([{":
                bracket_depth += 1
                max_depth = max(max_depth, bracket_depth)
            elif char in ")]}":
                bracket_depth -= 1

        if max_depth > 10:
            issues.append("deep_nesting")
            score += 0.2

        # Check for mixed delimiters
        delimiter_types = set()
        for match in re.finditer(r'["\'\`]{3,}|</?[a-zA-Z]+>|\[/?[A-Z]+\]', text):
            delimiter_types.add(match.group()[:3])

        if len(delimiter_types) > 3:
            issues.append("mixed_delimiters")
            score += 0.3

        triggered = len(issues) > 0
        score = min(1.0, score)

        return HeuristicResult(
            heuristic_type=HeuristicType.STRUCTURE,
            triggered=triggered,
            score=score,
            details={"issues": issues, "max_depth": max_depth},
            message=f"Structure issues: {', '.join(issues) or 'none'}",
        )

    def check_repetition(self, text: str) -> HeuristicResult:
        """Check for suspicious repetition patterns."""
        if len(text) < 20:
            return HeuristicResult(
                heuristic_type=HeuristicType.REPETITION,
                triggered=False,
                score=0.0,
                message="Text too short",
            )

        # Check character repetition
        prev_char = ""
        repeat_count = 0
        max_repeat = 0
        for char in text:
            if char == prev_char:
                repeat_count += 1
                max_repeat = max(max_repeat, repeat_count)
            else:
                repeat_count = 1
            prev_char = char

        # Check word repetition
        words = text.lower().split()
        if words:
            word_counts: Dict[str, int] = {}
            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1

            max_word_repeat = max(word_counts.values()) if word_counts else 0
            word_repeat_ratio = max_word_repeat / len(words)
        else:
            word_repeat_ratio = 0.0
            max_word_repeat = 0

        # Score
        score = 0.0
        issues = []

        if max_repeat > 10:
            score += 0.4
            issues.append("char_repeat")

        if word_repeat_ratio > self.config.max_repetition_ratio:
            score += 0.4
            issues.append("word_repeat")

        triggered = len(issues) > 0 or score > 0.3
        score = min(1.0, score)

        return HeuristicResult(
            heuristic_type=HeuristicType.REPETITION,
            triggered=triggered,
            score=score,
            details={
                "max_char_repeat": max_repeat,
                "word_repeat_ratio": word_repeat_ratio,
            },
            message=f"Repetition: char={max_repeat}, word_ratio={word_repeat_ratio:.2f}",
        )

    def check_special_chars(self, text: str) -> HeuristicResult:
        """Check for unusual special character usage."""
        if not text:
            return HeuristicResult(
                heuristic_type=HeuristicType.SPECIAL_CHARS,
                triggered=False,
                score=0.0,
            )

        # Count special characters
        special_count = sum(
            1 for c in text
            if not c.isalnum() and not c.isspace()
        )
        special_ratio = special_count / len(text)

        # Check for control characters
        control_chars = sum(1 for c in text if ord(c) < 32 and c not in '\n\r\t')

        # Check for unusual unicode
        unusual_unicode = sum(
            1 for c in text
            if ord(c) > 127 and not c.isalpha()
        )

        # Score
        score = 0.0
        issues = []

        if special_ratio > self.config.max_special_char_ratio:
            score += 0.4
            issues.append("high_special_ratio")

        if control_chars > 0:
            score += 0.3
            issues.append("control_chars")

        if unusual_unicode > len(text) * 0.1:
            score += 0.3
            issues.append("unusual_unicode")

        triggered = len(issues) > 0
        score = min(1.0, score)

        return HeuristicResult(
            heuristic_type=HeuristicType.SPECIAL_CHARS,
            triggered=triggered,
            score=score,
            details={
                "special_ratio": special_ratio,
                "control_chars": control_chars,
                "unusual_unicode": unusual_unicode,
            },
            message=f"Special chars: ratio={special_ratio:.2f}",
        )

    def check_language_switch(self, text: str) -> HeuristicResult:
        """Check for suspicious language/encoding switches."""
        # Simple detection of script changes
        scripts: Dict[str, int] = {
            "latin": 0,
            "cyrillic": 0,
            "cjk": 0,
            "other": 0,
        }

        for char in text:
            code = ord(char)
            if 0x0000 <= code <= 0x007F:  # Basic Latin
                scripts["latin"] += 1
            elif 0x0400 <= code <= 0x04FF:  # Cyrillic
                scripts["cyrillic"] += 1
            elif 0x4E00 <= code <= 0x9FFF:  # CJK
                scripts["cjk"] += 1
            elif code > 127:
                scripts["other"] += 1

        # Count non-zero scripts
        active_scripts = sum(1 for v in scripts.values() if v > 10)

        triggered = active_scripts > 2
        score = min(1.0, (active_scripts - 1) * 0.3) if active_scripts > 1 else 0.0

        return HeuristicResult(
            heuristic_type=HeuristicType.LANGUAGE_SWITCH,
            triggered=triggered,
            score=score,
            details={"scripts": scripts},
            message=f"Script distribution: {scripts}",
        )

    def check_instruction_density(self, text: str) -> HeuristicResult:
        """Check density of instruction-related words."""
        words = text.lower().split()
        if not words:
            return HeuristicResult(
                heuristic_type=HeuristicType.INSTRUCTION_DENSITY,
                triggered=False,
                score=0.0,
            )

        instruction_count = sum(
            1 for word in words
            if word in self.instruction_words
        )
        density = instruction_count / len(words)

        triggered = density > 0.1
        score = min(1.0, density * 5)

        return HeuristicResult(
            heuristic_type=HeuristicType.INSTRUCTION_DENSITY,
            triggered=triggered,
            score=score,
            details={
                "instruction_count": instruction_count,
                "density": density,
            },
            message=f"Instruction density: {density:.2f}",
        )

    def get_combined_score(self, results: List[HeuristicResult]) -> float:
        """Combine heuristic results into single score."""
        total_weight = 0.0
        weighted_score = 0.0

        for result in results:
            weight = self.config.weights.get(result.heuristic_type, 0.1)
            weighted_score += result.score * weight
            total_weight += weight

        if total_weight > 0:
            return weighted_score / total_weight
        return 0.0
