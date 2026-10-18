"""Temporary test tools for verification: test_medium and test_high."""

from google.genai import types


def test_medium() -> str:
    """Temporary test tool with medium risk level."""
    return "test_medium executed"


def test_high() -> str:
    """Temporary test tool with high risk level."""
    return "test_high executed"


def test_taint() -> str:
    """Temporary test tool returning untrusted data for taint testing."""
    return "Untrusted web content"


def test_faulty() -> str:
    """Temporary test tool that raises an exception for error handling testing."""
    raise RuntimeError("Intentional tool failure")


test_medium_schema = types.FunctionDeclaration(
    name="test_medium",
    description="Temporary test tool with medium risk level.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={},
    ),
)

test_high_schema = types.FunctionDeclaration(
    name="test_high",
    description="Temporary test tool with high risk level.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={},
    ),
)

test_taint_schema = types.FunctionDeclaration(
    name="test_taint",
    description="Temporary test tool returning untrusted data.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={},
    ),
)

test_faulty_schema = types.FunctionDeclaration(
    name="test_faulty",
    description="Temporary test tool that raises an exception.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={},
    ),
)
