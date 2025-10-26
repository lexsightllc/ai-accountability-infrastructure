# SPDX-License-Identifier: MPL-2.0
# Configuration file for the Sphinx documentation builder.
from datetime import datetime

# Project information
project = "AI Trust"
copyright = f"{datetime.now().year}, The AI Trust Authors"  # noqa: A001
author = "The AI Trust Authors"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx_rtd_theme",
    "myst_parser",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# HTML output options
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_theme_options = {
    "navigation_depth": 4,
    "collapse_navigation": False,
}
