class CliFailedCommandError(Exception):
    """cli command failed."""


class CliSyntaxError(Exception):
    """cli command had a syntax error."""


class UnexpectedApiReturnValueError(Exception):
    """exception raised when the API return value is unexpected"""

    def __init__(self, retval, message):
        self.retval = retval
        self.message = message
        super().__init__(message)
