VPP Custom Exceptions
=====================

.. autoexception:: custom_exceptions.VppError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.CaptureError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.CaptureUnexpectedPacketError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.CaptureMismatchError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.CaptureNoPacketsError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.CaptureTimeoutError
  :show-inheritance:
  :undoc-members:

.. autoexception:: hook.VppDiedError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.LispError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.RegistryError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.UnexpectedApiReturnValueError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.UnexpectedApiPositiveReturnValueError
  :show-inheritance:
  :undoc-members:

.. autoexception:: custom_exceptions.ApiInternalError
  :show-inheritance:
  :undoc-members:

Exception Hierarchy
###################
The following shows the VTL-specific exceptions in the context of the standard
Python exception hierarchy::

    BaseException
     +-- SystemExit
     +-- KeyboardInterrupt
     +-- GeneratorExit
     +-- Exception
          +-- StopIteration
          +-- StopAsyncIteration                    # Python 3
          +-- ApiInternalError                      # VPP Specific
          +-- ArithmeticError
          |    +-- FloatingPointError
          |    +-- OverflowError
          |    +-- ZeroDivisionError
          +-- AssertionError
          +-- AttributeError
          +-- BufferError
          +-- EOFError
          +-- ImportError
          |    +-- ModuleNotFoundError
          +-- LispError                             # VPP Specific
          +-- LookupError
          |    +-- IndexError
          |    +-- KeyError
          +-- MemoryError
          +-- NameError
          |    +-- UnboundLocalError
          +-- OSError
          |    +-- BlockingIOError                  # Python 3
          |    +-- ChildProcessError                # Python 3
          |    +-- ConnectionError                  # Python 3
          |    |    +-- BrokenPipeError             # Python 3
          |    |    +-- ConnectionAbortedError      # Python 3
          |    |    +-- ConnectionRefusedError      # Python 3
          |    |    +-- ConnectionResetError        # Python 3
          |    +-- FileExistsError                  # Python 3
          |    +-- FileNotFoundError                # Python 3
          |    +-- InterruptedError                 # Python 3
          |    +-- IsADirectoryError                # Python 3
          |    +-- NotADirectoryError               # Python 3
          |    +-- PermissionError                  # Python 3
          |    +-- ProcessLookupError               # Python 3
          |    +-- TimeoutError                     # Python 3
          |    +-- WindowsError (Windows)           # Python 2
          |    +-- VMSError (VMS)                   # Python 2
          +-- CaptureError                          # VPP Specific
          |    +-- CaptureUnexpectedPacketError     # VPP Specific
          |    +-- CaptureMismatchError             # VPP Specific
          |    |     +-- CaptureNoPacketsError      # VPP Specific
          |    +-- CaptureTimeoutError              # VPP Specific
          +-- ReferenceError
          +-- RegistryError                         # VPP Specific
          +-- RuntimeError
          |    +-- NotImplementedError
          |    +-- RecursionError                   # Python 3
          +-- SyntaxError
          |    +-- IndentationError
          |         +-- TabError
          +-- SystemError
          +-- TypeError
          +-- ValueError
          |    +-- UnicodeError
          |         +-- UnicodeDecodeError
          |         +-- UnicodeEncodeError
          |         +-- UnicodeTranslateError
          +-- UnexpectedApiPositiveReturnValueError # VPP Specific
          +-- UnexpectedApiReturnValueError         # VPP Specific
          +-- VppDiedError                          # VPP Specific
          +-- VppError                              # VPP Specific
          +-- Warning
               +-- DeprecationWarning
               +-- PendingDeprecationWarning
               +-- RuntimeWarning
               +-- SyntaxWarning
               +-- UserWarning
               +-- FutureWarning
               +-- ImportWarning
               +-- UnicodeWarning
               +-- BytesWarning
               +-- ResourceWarning                  # Python 3

