#!/usr/bin/python3

from enum import IntEnum, auto, unique


@unique
class TestResultCode(IntEnum):
    PASS = auto()
    FAIL = auto()
    ERROR = auto()
    SKIP = auto()
    TEST_RUN = auto()
    SKIP_CPU_SHORTAGE = auto()
    EXPECTED_FAIL = auto()
    UNEXPECTED_PASS = auto()
