"""Native tool: get_current_time."""

from datetime import datetime
from google.genai import types


def get_current_time() -> str:
    """Returns current local date and time as a string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


get_current_time_schema = types.FunctionDeclaration(
    name="get_current_time",
    description="Returns the current local date and time.",
    parameters=types.Schema(
        type=types.Type.OBJECT,
        properties={},
    ),
)
