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
# Debug CLI    {{'{#'}}clicmd}

The VPP network stack comes equipped with a set of commands that are useful
for debugging.

The easiest way to access the CLI (with proper permissions) is to use the
vppctl command:

```
sudo vppctl <cli-command>
```

The CLI parser matches static keyword strings, eventually invoking an action
function. Unambiguous partial keyword matching always occurs. The action
functions consume input until satisfied or until they fail. This model makes
for easy coding, but does not guarantee useful "help" output. It's up to the
CLI command writer to add useful help strings.

You can find the source code of CLI commands by searching for instances of the
@c VLIB_CLI_COMMAND macro in the code source files.

Please help maintain and improve this document to make and keep these commands
clear and useful!

@todo Document where to modify this CLI intro text.


## Debug and Telnet CLI

The debug CLI is enabled with the unix interactive parameter or startup
configuration option. This causes VPP to start without daemonizing and
presents a command line interface on the terminal where it is run.

The Telnet CLI is enabled with the `cli-listen localhost:5002` option which
will cause VPP to listen for TCP connections on the localhost address port
@c 5002. A Telnet client can then connect to this port (for example, `telnet
localhost 5002`) and will receive a command line prompt.

This configuration will enable both mechanisms:

```
unix {
  interactive
  cli-listen localhost:5002
}
```

The debug CLI can operate in line mode, which may be useful when running
inside an IDE like Emacs. This is enabled with the option
`unix cli-line-mode`. Several other options exist that alter how this
CLI works, see the @ref syscfg section for details.

The CLI starts with a banner graphic (which can be disabled) and a prompt. The
prompt will typically read `vpp` for a release version of VPP and `DBGvpp#`
for a development version with debugging enabled, for example:

        _______    _        _   _____  ___ 
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/    
    
    vpp# 

versus:

        _______    _        _   _____  ___ 
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/    
    
    DBGvpp# 

This prompt can be configured with the `unix cli-prompt` setting and the
banner is disabled with `unix cli-no-banner`.

## CLI features

The CLI has several editing features that make it easy to use.

- Cursor keys left/right will move the cursor within a command line;
  typing will insert at the cursor; erase will erase at the cursor.

- Ctrl-left/right will search for the start of the next word to
  the left or right.
- Home/end will jump the cursor to the start and end of the line.
- Cursor keys up/down and ^P/^N iterate through the command history
  buffer. Lines from the history buffer may be edited. New commands
  are added to the end of the buffer when executed; though
  duplicates of the previous command are not added.
- ^U erases the line contents from the left of the cursor to the
  start.
- ^K erases the contents from the cursor to the end.
- ^S/^R will search the command history forwards or in reverse for
  a command; start typing for matches to auto complete.
- ^L will clear the screen (if supported by the terminal) and repaint
  the prompt and any current line. The cursor position is also
  retained.
- The CLI can be closed with the quit command. Alternatively, ^D on
  an empty input line will also close the session. Closing the debug
  session will also shutdown VPP.

Output that exceeds the length of a terminal page will be buffered, up to a
limit.

- Space or page-down displays the next page.
- Enter or down-arrow displays the next line.
- Page-up goes back a page.
- Up-arrow goes up a line.
- Home/end jump to the start/end of the buffered output.
- The key q quits the pager. Space and enter will also quit the
  pager if the end of the buffer has been reached.

## Index of CLI commands

[TOC]
