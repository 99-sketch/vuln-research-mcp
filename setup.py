"""Setup configuration for vuln-research-mcp package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vuln-research-mcp",
    version="0.1.0",
    author="Penetration Testing Expert Agent",
    description="Vulnerability Research MCP Server for Penetration Testers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/vuln-research-mcp",
    packages=find_packages(where=".", include=["src*"]),
    python_requires=">=3.10",
    install_requires=[
        "mcp>=1.0.0",
        "httpx>=0.27.0",
        "pydantic>=2.0.0",
    ],
    extras_require={
        "dev": [
            "pytest",
            "pytest-asyncio",
            "black",
            "isort",
            "mypy",
            "build",
            "twine",
        ]
    },
    entry_points={
        "console_scripts": [
            "vuln-research-mcp=src.server:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    license="MIT",
)
