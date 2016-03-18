;;; cli-cmd-skel.el - cli command skeleton

(require 'skeleton)

(define-skeleton skel-cli-cmd
"Insert a CLI command "
nil
'(setq cmd-name (skeleton-read "Command Name: "))
'(setq path (skeleton-read "Path: "))

"
static clib_error_t *
" cmd-name "_command_fn (vlib_main_t * vm,
		 unformat_input_t * input,
		 vlib_cli_command_t * cmd)
{
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat (input, \"whatever %d\", &whatever))
	    ;
	else
	    return clib_error_return (0, \"unknown input `%U'\",
				      format_unformat_error, input);
    }
    return 0;
}

VLIB_CLI_COMMAND (" cmd-name "_command, static) = {
    .path = \"" path "\",
    .short_help = \"" path "\",
    .function = " cmd-name "_command_fn,
};
")
