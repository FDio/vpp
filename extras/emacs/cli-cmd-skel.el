;;; Copyright (c) 2016 Cisco and/or its affiliates.
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at:
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

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
