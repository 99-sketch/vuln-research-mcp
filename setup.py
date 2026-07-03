"""Setup configuration for vuln-research-mcp package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="vuln-research-mcp",
    version="2.0.0",
    author="Penetration Testing Expert Agent",
    description="Vulnerability Research MCP Server - Security Intelligence Workstation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/99-sketch/vuln-research-mcp",
    packages=find_packages(where=".", include=["src*"]),
    python_requires=">=3.10",
    install_requires=[
        "mcp>=1.0.0",
        "httpx>=0.27.0",
        "dnspython>=2.4.0",
        "diskcache>=5.6.0",
        "PyYAML>=6.0",
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
        ],
    },
    entry_points={
        "console_scripts": [
            "vuln-research-mcp=src.server:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
