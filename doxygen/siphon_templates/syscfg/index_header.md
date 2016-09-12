{#
# Copyright (c) 2016 Comcast Cable Communications Management, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#}
# Startup Configuration    {{'{#'}}syscfg}

The VPP network stack comes with several configuration options that can be
provided either on the command line or in a configuration file.

Specific applications built on the stack have been known to require a dozen
arguments, depending on requirements. This section describes commonly-used
options and parameters.

You can find command-line argument parsers in the source code by searching for
instances of the `VLIB_CONFIG_FUNCTION` macro. The invocation
`VLIB_CONFIG_FUNCTION(foo_config, "foo")` will cause the function
`foo_config` to receive all the options and values supplied in a parameter
block named "`foo`", for example: `foo { arg1 arg2 arg3 ... }`.

@todo Tell the nice people where this document lives so that the might
help improve it!

## Command-line arguments

Parameters are grouped by a section name. When providing more than one
parameter to a section all parameters for that section must be wrapped in
curly braces.

```
/usr/bin/vpp unix { interactive cli-listen 127.0.0.1:5002 }
```

Which will produce output similar to this:

    <startup diagnostic messages>
        _______    _        _   _____  ___ 
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/    
    
    vpp# <start-typing>

When providing only one such parameter the braces are optional. For example,
the following command argument, `unix interactive` does not have braces:

```
/usr/bin/vpp unix interactive
```

The command line can be presented as a single string or as several; anything
given on the command line is concatenated with spaces into a single string
before parsing.

VPP applications must be able to locate their own executable images. The
simplest way to ensure this will work is to invoke a VPP application by giving
its absolute path; for example: `/usr/bin/vpp <options>`. At startup, VPP
applications parse through their own ELF-sections (primarily) to make lists
of init, configuration, and exit handlers.

When developing with VPP, in _gdb_ it's often sufficient to start an application
like this at the `(gdb)` prompt:

```
run unix interactive
```

## Configuration file

It is also possible to supply parameters in a startup configuration file the
path of which is provided to the VPP application on its command line.

The format of the configuration file is a simple text file with the same
content as the command line but with the benefit of being able to use newlines
to make the content easier to read. For example:

```
unix {
  nodaemon
  log /tmp/vpp.log
  full-coredump
  cli-listen localhost:5002
}
api-trace {
  on
}
dpdk {
  dev 0000:03:00.0
}
```

VPP is then instructed to load this file with the `-c` option:

```
/usr/bin/vpp -c /etc/vpp/startup.conf
```

## Index of startup command sections

[TOC]

