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
