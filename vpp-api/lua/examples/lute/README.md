LUTE: Lua Unit Test Environment

This is a small helper utility to automate some simple tests
that one might need to do.

Think of it as a hybrid of a screen and expect who
also took some habits from HTML inline code.

It is quite probably useless for building anything serious,
but practice shows it is quite efficient at allowing
convenient temporary quick tests, and for something
that was written over a course of a couple of evenings it
is quite a nice little helper tool.

It allows do launch and drive multiple shell sessions,
and by virtue of having been written in Lua, it of course
also allows to add the business logic using the Lua code.

If you launch the lute without parameters, it gives you
the interactive shell to execute the commands in.

If you launch it with an argument, it will attempt to
read and execute the commands from the file.

Commands:

shell FOO

  spawn a shell in a new PTY under the label FOO.

run FOO bar

  Send "bar" keystrokes followed by "ENTER" to the session FOO

  Special case: "break" word on its own gets translated into ^C being sent.

cd FOO

  "change domain" into session FOO. All subsequent inputs will go,
  line-buffered, into the session FOO. To jump back up, use ^D (Control-D),
  or within the file, use ^D^D^D (caret D caret D caret D on its own line)

expect FOO blablabla

  Pause further interpretation of the batch mode until you see "blablabla"
  in the output of session FOO, or until timeout happens.

sleep N

  Sleep an integer N seconds, if you are in batch mode.

echo blabla

  Echo the remainder of the line to standard output.

For Lua code, there is a pre-existing pseudo-session called "lua",
which accepts "run lua" command which does what you would expect
(evaluate the rest of the string in Lua context - being the same
as lute itself). Also you can do "cd lua" and get into a
multiline-enabled interpreter shell.

This way for the VPP case you can automate some of the things in your routine
that you would have to have done manually, and test drive API as well
as use the realistic native OS components to create the environment around it.


