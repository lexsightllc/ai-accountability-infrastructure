# SPDX-License-Identifier: MPL-2.0
"""Setuptools configuration for backward compatibility.

This file is only needed for tools that don't support pyproject.toml yet.
It should be kept minimal and delegate to pyproject.toml.
"""
from setuptools import setup

if __name__ == "__main__":
    setup()
