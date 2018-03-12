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

;;; elog-enum-skel.el - enum elog skeleton

(require 'skeleton)

(define-skeleton skel-elog-enum
"Insert a skeleton enum event definition"
nil
'(setq function-name (skeleton-read "Function: "))
'(setq label (skeleton-read "Label: "))

"

/* $$$ May or may not be needed */
#include <vlib/vlib.h>
#include <vppinfra/elog.h>

static inline void " function-name " (u8 which)
{
  ELOG_TYPE_DECLARE (e) = 
    {
      .format = \"" label ": %s\",
      .format_args = \"t1\",
      .n_enum_strings = 2,
      .enum_strings = 
      {
        \"string 1\",
        \"string 2\", 
      },
    };
  struct { u8 which;} * ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->which = which;
}

")
