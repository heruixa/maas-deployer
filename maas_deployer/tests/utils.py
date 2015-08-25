#
# Copyright 2015 Canonical, Ltd.
#


class UnitTestException(Exception):
    """
    Use this in tests rather than generic Exception to avoid unexpectedly
    catching exceptions that also inherit from Exception.
    """
    pass
