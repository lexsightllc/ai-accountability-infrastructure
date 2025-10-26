"""Tests for the canonicalization module."""

import json
import math
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Union

import pytest
from pydantic import BaseModel

from ai_trust.core.canonicalization import (
    CanonicalizationError,
    canonicalize,
    canonical_json_dumps,
    verify_canonical_equivalence,
)


class SampleModel(BaseModel):
    """Test model for Pydantic canonicalization."""
    
    name: str
    value: float
    tags: List[str]
    metadata: Dict[str, Any] = {}
    
    class Config:
        json_encoders = {
            float: lambda v: float(Decimal(str(v)).normalize())
        }


def test_canonicalize_primitive_types():
    """Test canonicalization of primitive types."""
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(42) == b"42"
    assert canonicalize(3.14) == b"3.14"
    assert canonicalize("hello") == b'"hello"'


def test_canonicalize_lists():
    """Test canonicalization of lists."""
    assert canonicalize([]) == b"[]"
    assert canonicalize([1, 2, 3]) == b"[1,2,3]"
    assert canonicalize(["a", "b", "c"]) == b'["a","b","c"]'
    assert canonicalize([1, "two", [3, 4], {"five": 5}]) == b'[1,"two",[3,4],{"five":5}]'


def test_canonicalize_objects():
    """Test canonicalization of dictionaries and objects."""
    # Test with dict
    assert canonicalize({}) == b"{}"
    assert (
        canonicalize({"b": 2, "a": 1}) 
        == b'{"a":1,"b":2}'
    )
    
    # Test with nested structures
    data = {
        "b": [2, 3, 1],
        "a": {"z": 26, "y": 25, "x": 24},
        "c": "test",
    }
    expected = b'{"a":{"x":24,"y":25,"z":26},"b":[2,3,1],"c":"test"}'
    assert canonicalize(data) == expected


def test_canonicalize_floats():
    """Test canonicalization of floating-point numbers."""
    # Integers stay as integers
    assert canonicalize(42.0) == b"42"
    
    # Simple floats
    assert canonicalize(3.14) == b"3.14"
    assert canonicalize(0.123456789) == b"0.123456789"
    
    # Scientific notation
    assert canonicalize(1e6) == b"1000000"
    assert canonicalize(1.23e-4) == b"0.000123"
    
    # Edge cases
    assert canonicalize(0.0) == b"0"
    assert canonicalize(-0.0) == b"0"
    
    # Non-finite numbers raise an error
    with pytest.raises(CanonicalizationError):
        canonicalize(float('inf'))
    with pytest.raises(CanonicalizationError):
        canonicalize(float('nan'))


def test_canonicalize_strings():
    """Test canonicalization of strings with special characters."""
    # Basic strings
    assert canonicalize("hello") == b'"hello"'
    
    # Strings with special characters
    assert canonicalize("line\nbreak") == b'"line\\nbreak"'
    assert canonicalize("quote\"here") == b'"quote\\"here"'
    assert canonicalize("backslash\\here") == b'"backslash\\\\here"'
    
    # Unicode characters
    assert canonicalize("üñîçø∂é") == '\"üñîçø∂é\"'.encode('utf-8')


def test_canonicalize_pydantic_models():
    """Test canonicalization of Pydantic models."""
    model = SampleModel(
        name="test",
        value=3.14,
        tags=["a", "b", "c"],
        metadata={"version": 1, "active": True},
    )
    
    # Should be equivalent to its dict representation
    expected = canonicalize({
        "name": "test",
        "value": 3.14,
        "tags": ["a", "b", "c"],
        "metadata": {"version": 1, "active": True},
    })
    
    assert canonicalize(model) == expected


def test_verify_canonical_equivalence():
    """Test the verify_canonical_equivalence function."""
    # Equal primitives
    assert verify_canonical_equivalence(42, 42)
    assert verify_canonical_equivalence("test", "test")
    
    # Equal objects with different key order
    assert verify_canonical_equivalence(
        {"a": 1, "b": 2},
        {"b": 2, "a": 1}
    )
    
    # Equal lists with different order are not considered equivalent
    assert not verify_canonical_equivalence([1, 2, 3], [3, 2, 1])
    
    # Different values
    assert not verify_canonical_equivalence(42, 43)
    assert not verify_canonical_equivalence("a", "b")


def test_canonical_json_dumps():
    """Test the canonical_json_dumps convenience function."""
    data = {"b": 2, "a": 1}
    assert canonical_json_dumps(data) == '{"a":1,"b":2}'
    
    # Should be equivalent to decoding the bytes from canonicalize()
    assert canonical_json_dumps(data) == canonicalize(data).decode("utf-8")


def test_error_handling():
    """Test error conditions raise appropriate exceptions."""
    # Unsupported types
    with pytest.raises(CanonicalizationError):
        canonicalize(datetime.now())
    
    # Non-string dictionary keys
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "one", 2: "two"})
    
    # Invalid numbers
    with pytest.raises(CanonicalizationError):
        canonicalize(float('inf'))
    with pytest.raises(CanonicalizationError):
        canonicalize(float('nan'))


def test_deterministic_output():
    """Ensure the same input always produces the same output."""
    data = {
        "b": [2, 3, 1],
        "a": 1,
        "c": {"z": 26, "y": 25, "x": 24},
    }
    
    # Multiple calls should produce identical output
    output1 = canonicalize(data)
    output2 = canonicalize(data)
    assert output1 == output2
    
    # Different key order should produce same output
    data2 = {
        "c": {"y": 25, "x": 24, "z": 26},
        "a": 1,
        "b": [2, 3, 1],
    }
    output3 = canonicalize(data2)
    assert output1 == output3


def test_complex_nested_structures():
    """Test with complex nested structures."""
    data = {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "timestamp": "2023-04-12T15:30:00Z",
        "model": {
            "name": "gpt-4",
            "version": "2023.03.14",
            "parameters": {
                "temperature": 0.7,
                "max_tokens": 1000,
                "top_p": 1.0
            }
        },
        "inputs": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, world!"}
        ],
        "output": {
            "content": "Hello! How can I help you today?",
            "finish_reason": "stop"
        },
        "metadata": {
            "environment": "production",
            "deployment": "us-west-2",
            "tags": ["v1.0.0", "production"]
        }
    }
    
    # Just verify it doesn't raise and produces a deterministic result
    result = canonicalize(data)
    assert isinstance(result, bytes)
    assert len(result) > 0
    
    # Round-trip through JSON to verify it's valid
    parsed = json.loads(result.decode('utf-8'))
    assert parsed["id"] == data["id"]
    assert parsed["model"]["name"] == data["model"]["name"]
    assert len(parsed["inputs"]) == 2
