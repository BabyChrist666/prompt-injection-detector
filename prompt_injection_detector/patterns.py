"""
Pattern matching for prompt injection detection.

Defines injection patterns and regex-based detection.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern, Tuple
from enum import Enum


class PatternCategory(Enum):
    """Categories of injection patterns."""
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_MANIPULATION = "role_manipulation"
    CONTEXT_ESCAPE = "context_escape"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK = "jailbreak"
    ENCODING_ABUSE = "encoding_abuse"
    DELIMITER_ABUSE = "delimiter_abuse"
    PROMPT_LEAKING = "prompt_leaking"


@dataclass
class InjectionPattern:
    """A pattern for detecting injection attempts."""
    name: str
    pattern: str
    category: PatternCategory
    severity: float = 0.5  # 0.0 to 1.0
    description: str = ""
    examples: List[str] = field(default_factory=list)
    flags: int = re.IGNORECASE

    def __post_init__(self):
        self._compiled: Optional[Pattern] = None

    @property
    def compiled(self) -> Pattern:
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, self.flags)
        return self._compiled

    def match(self, text: str) -> Optional[re.Match]:
        """Find first match in text."""
        return self.compiled.search(text)

    def findall(self, text: str) -> List[str]:
        """Find all matches in text."""
        return self.compiled.findall(text)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "pattern": self.pattern,
            "category": self.category.value,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class PatternMatch:
    """Result of a pattern match."""
    pattern: InjectionPattern
    matched_text: str
    start: int
    end: int
    context: str = ""

    def to_dict(self) -> dict:
        return {
            "pattern_name": self.pattern.name,
            "category": self.pattern.category.value,
            "severity": self.pattern.severity,
            "matched_text": self.matched_text,
            "start": self.start,
            "end": self.end,
            "context": self.context,
        }


class PatternMatcher:
    """
    Matches text against injection patterns.

    Provides pattern-based detection of prompt injection attempts.
    """

    def __init__(self, patterns: Optional[List[InjectionPattern]] = None):
        self.patterns = patterns or self._default_patterns()

    def _default_patterns(self) -> List[InjectionPattern]:
        """Load default injection patterns."""
        return [
            # Instruction Override
            InjectionPattern(
                name="ignore_instructions",
                pattern=r"ignore\s+(all\s+)?(previous\s+)?(instructions?|prompts?|rules?)",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                severity=0.9,
                description="Attempts to override previous instructions",
            ),
            InjectionPattern(
                name="forget_instructions",
                pattern=r"forget\s+(all\s+)?(previous\s+)?(instructions?|prompts?|context)",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                severity=0.9,
                description="Attempts to make model forget instructions",
            ),
            InjectionPattern(
                name="disregard_instructions",
                pattern=r"disregard\s+(all\s+)?(previous\s+)?(instructions?|prompts?)",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                severity=0.9,
                description="Attempts to disregard instructions",
            ),
            InjectionPattern(
                name="new_instructions",
                pattern=r"your\s+new\s+(instructions?|task|role|purpose)\s+(is|are)",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                severity=0.85,
                description="Attempts to set new instructions",
            ),
            InjectionPattern(
                name="override_system",
                pattern=r"(override|bypass|circumvent)\s+(the\s+)?(system|base)\s+(prompt|instructions?)",
                category=PatternCategory.INSTRUCTION_OVERRIDE,
                severity=0.95,
                description="Direct system override attempt",
            ),

            # Role Manipulation
            InjectionPattern(
                name="pretend_role",
                pattern=r"(pretend|act|behave)\s+(you\s+are|as\s+if|like)\s+(a\s+)?",
                category=PatternCategory.ROLE_MANIPULATION,
                severity=0.7,
                description="Attempts to change assistant role",
            ),
            InjectionPattern(
                name="you_are_now",
                pattern=r"you\s+are\s+now\s+(a|an|the)\s+",
                category=PatternCategory.ROLE_MANIPULATION,
                severity=0.75,
                description="Attempts to redefine identity",
            ),
            InjectionPattern(
                name="roleplay_request",
                pattern=r"(roleplay|role-play|rp)\s+as\s+",
                category=PatternCategory.ROLE_MANIPULATION,
                severity=0.6,
                description="Roleplay manipulation attempt",
            ),
            InjectionPattern(
                name="imagine_you",
                pattern=r"imagine\s+(that\s+)?you\s+(are|were|have)",
                category=PatternCategory.ROLE_MANIPULATION,
                severity=0.6,
                description="Hypothetical role manipulation",
            ),

            # Context Escape
            InjectionPattern(
                name="end_of_prompt",
                pattern=r"(END|end)\s+(of\s+)?(PROMPT|prompt|SYSTEM|system|INPUT|input)",
                category=PatternCategory.CONTEXT_ESCAPE,
                severity=0.85,
                description="Attempts to mark end of prompt",
            ),
            InjectionPattern(
                name="delimiter_injection",
                pattern=r"(\[/?INST\]|\[/?SYS\]|<\|im_start\|>|<\|im_end\|>|###|\n---\n)",
                category=PatternCategory.CONTEXT_ESCAPE,
                severity=0.8,
                description="Special delimiter injection",
            ),
            InjectionPattern(
                name="system_tag",
                pattern=r"</?system>|<<SYS>>|<\|system\|>",
                category=PatternCategory.CONTEXT_ESCAPE,
                severity=0.85,
                description="System tag injection",
            ),
            InjectionPattern(
                name="assistant_injection",
                pattern=r"(Assistant|AI|Bot):\s*",
                category=PatternCategory.CONTEXT_ESCAPE,
                severity=0.7,
                description="Attempts to inject assistant response",
            ),

            # Jailbreak Patterns
            InjectionPattern(
                name="dan_jailbreak",
                pattern=r"(DAN|do\s+anything\s+now|jailbreak|jailbroken)",
                category=PatternCategory.JAILBREAK,
                severity=0.95,
                description="DAN jailbreak attempt",
            ),
            InjectionPattern(
                name="developer_mode",
                pattern=r"(developer|dev)\s+mode|enable\s+developer",
                category=PatternCategory.JAILBREAK,
                severity=0.9,
                description="Developer mode jailbreak",
            ),
            InjectionPattern(
                name="unrestricted_mode",
                pattern=r"(unrestricted|unfiltered|uncensored)\s+(mode|version|output)",
                category=PatternCategory.JAILBREAK,
                severity=0.9,
                description="Unrestricted mode request",
            ),
            InjectionPattern(
                name="bypass_safety",
                pattern=r"(bypass|disable|ignore|remove)\s+(safety|content|ethical)\s+(filter|restriction|guideline)",
                category=PatternCategory.JAILBREAK,
                severity=0.95,
                description="Safety bypass attempt",
            ),

            # Data Exfiltration
            InjectionPattern(
                name="reveal_prompt",
                pattern=r"(reveal|show|display|print|output)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?)",
                category=PatternCategory.DATA_EXFILTRATION,
                severity=0.8,
                description="Attempts to reveal system prompt",
            ),
            InjectionPattern(
                name="repeat_everything",
                pattern=r"repeat\s+(everything|all|back)\s+(above|before|you\s+were\s+told)",
                category=PatternCategory.DATA_EXFILTRATION,
                severity=0.85,
                description="Attempts to leak previous context",
            ),
            InjectionPattern(
                name="training_data",
                pattern=r"(training|internal)\s+(data|information|details)",
                category=PatternCategory.DATA_EXFILTRATION,
                severity=0.7,
                description="Training data extraction attempt",
            ),

            # Prompt Leaking
            InjectionPattern(
                name="what_is_prompt",
                pattern=r"what\s+(is|are|was)\s+(your|the)\s+(system\s+)?(prompt|instructions?)",
                category=PatternCategory.PROMPT_LEAKING,
                severity=0.75,
                description="Direct prompt inquiry",
            ),
            InjectionPattern(
                name="summarize_instructions",
                pattern=r"(summarize|explain|describe)\s+(your\s+)?(system\s+)?(instructions?|guidelines?|rules?)",
                category=PatternCategory.PROMPT_LEAKING,
                severity=0.7,
                description="Prompt summarization request",
            ),

            # Encoding Abuse
            InjectionPattern(
                name="base64_pattern",
                pattern=r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
                category=PatternCategory.ENCODING_ABUSE,
                severity=0.5,
                description="Potential base64 encoded content",
            ),
            InjectionPattern(
                name="unicode_abuse",
                pattern=r"[\u200b-\u200f\u2028-\u202f\u2060-\u206f]",
                category=PatternCategory.ENCODING_ABUSE,
                severity=0.6,
                description="Invisible unicode characters",
            ),
            InjectionPattern(
                name="hex_encoded",
                pattern=r"\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}",
                category=PatternCategory.ENCODING_ABUSE,
                severity=0.5,
                description="Hex encoded characters",
            ),
        ]

    def add_pattern(self, pattern: InjectionPattern) -> None:
        """Add a custom pattern."""
        self.patterns.append(pattern)

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name."""
        original = len(self.patterns)
        self.patterns = [p for p in self.patterns if p.name != name]
        return len(self.patterns) < original

    def match(self, text: str, context_window: int = 50) -> List[PatternMatch]:
        """
        Find all pattern matches in text.

        Args:
            text: Text to analyze
            context_window: Characters to include in context

        Returns:
            List of PatternMatch objects
        """
        matches = []

        for pattern in self.patterns:
            for match in pattern.compiled.finditer(text):
                # Get context around match
                start = max(0, match.start() - context_window)
                end = min(len(text), match.end() + context_window)
                context = text[start:end]

                matches.append(PatternMatch(
                    pattern=pattern,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    context=context,
                ))

        return matches

    def match_by_category(
        self,
        text: str,
        category: PatternCategory,
    ) -> List[PatternMatch]:
        """Match only patterns in a specific category."""
        matches = []
        for pattern in self.patterns:
            if pattern.category == category:
                for match in pattern.compiled.finditer(text):
                    matches.append(PatternMatch(
                        pattern=pattern,
                        matched_text=match.group(),
                        start=match.start(),
                        end=match.end(),
                    ))
        return matches

    def get_patterns_by_category(
        self,
        category: PatternCategory,
    ) -> List[InjectionPattern]:
        """Get all patterns in a category."""
        return [p for p in self.patterns if p.category == category]

    def get_pattern(self, name: str) -> Optional[InjectionPattern]:
        """Get a pattern by name."""
        for p in self.patterns:
            if p.name == name:
                return p
        return None

    def get_max_severity(self, matches: List[PatternMatch]) -> float:
        """Get maximum severity from matches."""
        if not matches:
            return 0.0
        return max(m.pattern.severity for m in matches)
