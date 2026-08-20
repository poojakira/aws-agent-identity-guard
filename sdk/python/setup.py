"""Setup script for aws-agent-identity-guard-sdk."""

from setuptools import setup, find_packages

setup(
    name="aws-agent-identity-guard-sdk",
    version="1.0.0",
    description="Python SDK for AWS Agent Identity Guard - runtime authorization for AI agents",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="AWS Agent Identity Guard Contributors",
    license="Apache-2.0",
    url="https://github.com/aws/agent-identity-guard",
    project_urls={
        "Documentation": "https://github.com/aws/agent-identity-guard/wiki",
        "Source": "https://github.com/aws/agent-identity-guard",
        "Issues": "https://github.com/aws/agent-identity-guard/issues",
    },
    packages=find_packages(where="../../src"),
    package_dir={"": "../../src"},
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "responses>=0.23.0",
            "mypy>=1.0.0",
            "ruff>=0.1.0",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
    keywords="aws agent identity authorization security ai",
)
