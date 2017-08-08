""" debug utilities """

import os
import pexpect

gdb_path = '/usr/bin/gdb'


def spawn_gdb(binary_path, core_path, logger):
    if os.path.isfile(gdb_path) and os.access(gdb_path, os.X_OK):
        # automatically attach gdb
        gdb_cmdline = "%s %s %s" % (gdb_path, binary_path, core_path)
        gdb = pexpect.spawn(gdb_cmdline)
        gdb.interact()
        try:
            gdb.terminate(True)
        except:
            pass
        if gdb.isalive():
            raise Exception("GDB refused to die...")
    else:
        logger.error("Debugger '%s' does not exist or is not an "
                     "executable.." % gdb_path)
