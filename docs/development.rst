# SPDX-License-Identifier: MPL-2.0
Development
===========

Setting Up the Development Environment
--------------------------------------

1. Fork and clone the repository:

   .. code-block:: bash

      git clone https://github.com/your-username/ai-trust.git
      cd ai-trust

2. Create and activate a virtual environment:

   .. code-block:: bash

      python -m venv venv
      source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install development dependencies:

   .. code-block:: bash

      pip install -e '.[dev,server,crypto]'

4. Set up pre-commit hooks:

   .. code-block:: bash

      pre-commit install

Running Tests
-------------

.. code-block:: bash

   # Run all tests
   pytest

   # Run tests with coverage
   pytest --cov=ai_trust --cov-report=term-missing

   # Run a specific test
   pytest tests/unit/test_module.py::test_function

Code Style
----------

We use the following tools to maintain code quality:

- **Black** for code formatting
- **isort** for import sorting
- **ruff** for linting
- **mypy** for type checking

Run all code quality checks:

.. code-block:: bash

   make lint

Documentation
-------------

Build the documentation:

.. code-block:: bash

   cd docs
   make html

The documentation will be available in ``docs/_build/html/``.
