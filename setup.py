"""Setup script for prompt-injection-detector."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="prompt-injection-detector",
    version="0.1.0",
    author="BabyChrist666",
    author_email="babychrist666@example.com",
    description="Real-time detection of prompt injection attacks for LLM applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BabyChrist666/prompt-injection-detector",
    packages=find_packages(exclude=["tests", "tests.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Pure Python - no external dependencies
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ],
    },
    keywords=[
        "prompt-injection",
        "llm",
        "security",
        "ai-safety",
        "nlp",
        "machine-learning",
        "detection",
        "sanitization",
    ],
    project_urls={
        "Bug Reports": "https://github.com/BabyChrist666/prompt-injection-detector/issues",
        "Source": "https://github.com/BabyChrist666/prompt-injection-detector",
        "Documentation": "https://babychrist666.github.io/prompt-injection-detector/",
    },
)
