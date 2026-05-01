#!/usr/bin/env python3
"""
Setup script for Mini IDS
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mini-ids",
    version="1.0.0",
    author="Mini IDS Contributors",
    description="A lightweight Intrusion Detection System using Scapy for educational purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/Mini-IDS",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "scapy>=2.4.3",
    ],
    entry_points={
        "console_scripts": [
            "mini-ids=mini_ids.ids:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Security",
    ],
)
