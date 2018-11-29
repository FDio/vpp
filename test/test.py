import subprocess
import errno

try:
    s = subprocess.Popen('foo')
except OSError as e:
    if e.errno == errno.ENOENT:
        print(e.strerror)
    raise