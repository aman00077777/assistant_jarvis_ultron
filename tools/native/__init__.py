"""Native tools package."""

import os
from tools.native.time_tool import get_current_time, get_current_time_schema

__all__ = [
    "get_current_time",
    "get_current_time_schema",
]

if os.getenv("ASSISTANT_TEST") == "1":
    from tools.native.test_tools import (
        test_faulty,
        test_faulty_schema,
        test_high,
        test_high_schema,
        test_medium,
        test_medium_schema,
        test_taint,
        test_taint_schema,
    )
    __all__.extend([
        "test_medium",
        "test_medium_schema",
        "test_high",
        "test_high_schema",
        "test_taint",
        "test_taint_schema",
        "test_faulty",
        "test_faulty_schema",
    ])

