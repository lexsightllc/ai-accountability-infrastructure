# SPDX-License-Identifier: MPL-2.0
Getting Started
===============

Installation
------------

.. code-block:: bash

   pip install ai-trust

Basic Usage
-----------

.. code-block:: python

   from ai_trust import create_receipt, verify_receipt

   from ai_trust.core import KeyPair
   key_pair = KeyPair.generate()

   data = {"model": "gpt-4", "input": "Hello", "output": "Hi there!"}
   receipt = create_receipt(data, key_pair)
   is_valid = verify_receipt(receipt, key_pair.public_bytes())
   print(f"Receipt is valid: {is_valid}")

Configuration
-------------

Create a ``.env`` file in your project root:

.. code-block:: bash

   # Server configuration
   HOST=0.0.0.0
   PORT=8000

   # Database
   DATABASE_URL=sqlite:///./ai_trust.db

   # Security
   SECRET_KEY=your-secret-key
