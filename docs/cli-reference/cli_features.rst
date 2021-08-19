.. _cli_features:

CLI features
============

The CLI has several editing features that make it easy to use.

- Cursor keys ``left/right`` will move the cursor within a command line;
  typing will insert at the cursor; erase will erase at the cursor.

- ``Ctrl-left/right`` will search for the start of the next word to
  the left or right.
- ``Home/end`` will jump the cursor to the start and end of the line.
- Cursor keys up/down and ``^P/^N`` iterate through the command history
  buffer. Lines from the history buffer may be edited. New commands
  are added to the end of the buffer when executed; though
  duplicates of the previous command are not added.
- ``^U`` erases the line contents from the left of the cursor to the
  start.
- ``^K`` erases the contents from the cursor to the end.
- ``^S/^R`` will search the command history forwards or in reverse for
  a command; start typing for matches to auto complete.
- ``^L`` will clear the screen (if supported by the terminal) and repaint
  the prompt and any current line. The cursor position is also
  retained.
- The CLI can be closed with the quit command. Alternatively, ``^D`` on
  an empty input line will also close the session. Closing the debug
  session will also shutdown VPP.

Output that exceeds the length of a terminal page will be buffered, up to a
limit.

- ``Space`` or ``page-down`` displays the next page.
- ``Enter`` or ``down-arrow`` displays the next line.
- ``Page-up`` goes back a page.
- ``Up-arrow`` goes up a line.
- ``Home/end`` jump to the start/end of the buffered output.
- The key ``q`` quits the pager. ``Space`` and ``enter`` will also quit the
  pager if the end of the buffer has been reached.