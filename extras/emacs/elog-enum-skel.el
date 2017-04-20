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
