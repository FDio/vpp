;;; config-skel.el - config function command skeleton

(require 'skeleton)

(define-skeleton skel-config
"Insert a vlib config skeleton "
nil
'(setq cfg-name (skeleton-read "Config Class Name: "))

"
static clib_error_t *
" cfg-name "_config (vlib_main_t * vm, unformat_input_t * input)
{
    u32 whatever;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	if (unformat (input, \"whatever %d\", &whatever))
	    ;
	else
	    return clib_error_return (0, \"unknown input `%U'\",
				      format_unformat_error, input);
    }

    return 0;
}

VLIB_CONFIG_FUNCTION (" cfg-name "_config, \"" cfg-name "\");
")
