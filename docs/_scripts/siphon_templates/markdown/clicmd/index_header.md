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
.. _cmdreference:

Debug CLI Reference
===================

The VPP network stack comes equipped with a set of commands that are useful
for debugging.

The easiest way to access the CLI (with proper permissions) is to use the
vppctl command:

.. code-block:: console

    sudo vppctl <cli-command>


The CLI parser matches static keyword strings, eventually invoking an action
function. Unambiguous partial keyword matching always occurs. The action
functions consume input until satisfied or until they fail. This model makes
for easy coding, but does not guarantee useful "help" output. It's up to the
CLI command writer to add useful help strings.

You can find the source code of CLI commands by searching for instances of the
``VLIB_CLI_COMMAND`` macro in the code source files.

Please help maintain and improve this document to make and keep these commands
clear and useful!

.. toctree::
    :maxdepth: 2

    gettingstarted/index
    interface/index.rst
