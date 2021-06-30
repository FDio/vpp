# Utility Functions

import os
import sys
from functools import wraps
import tempfile


# Set an alternative test logging dir
# (TODO): Update log_dir via cmdline args
log_dir = None


def alt_logdir(func):
    """Decorator for setting an alternative unittest log directory."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        test_log_dir = log_dir or os.environ.get('LOG_DIR')
        cls = args[0]
        # Debug attach log location is unchanged
        if test_log_dir and not cls.debug_attach:
            if not os.path.isdir(test_log_dir):
                print(f"Error: log directory {test_log_dir} does not exist")
                sys.exit(1)
            if not os.access(test_log_dir, os.W_OK):
                print(f"Permission error accessing log dir: {test_log_dir}")
                sys.exit(1)
            print(f"Unittest run will be logged to {test_log_dir}")
            return tempfile.mkdtemp(
                prefix='vpp-unittest-%s-' % cls.__name__,
                dir=test_log_dir)
        else:
            return func(*args, **kwargs)
    return wrapper
