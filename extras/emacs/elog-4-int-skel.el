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

;;; elog-4-int-skel.el - 4 integer elog skeleton

(require 'skeleton)

(define-skeleton skel-elog-4-int
"Insert a skeleton 4-integer event definition"
nil
'(setq function-name (skeleton-read "Function: "))
'(setq label (skeleton-read "Label: "))

"

/* $$$ May or may not be needed */
#include <vlib/vlib.h>
#include <vppinfra/elog.h>

static inline void " function-name " (u32 *data)
{
  ELOG_TYPE_DECLARE(e) = 
    {
      .format = \"" label ": first %d second %d third %d fourth %d\",
      .format_args = \"i4i4i4i4\",
    };
  struct { u32 data[4];} * ed;
  ed = ELOG_DATA (&vlib_global_main.elog_main, e);
  ed->data[0] = data[0];
  ed->data[1] = data[1];
  ed->data[2] = data[2];
  ed->data[3] = data[3];
}
")
