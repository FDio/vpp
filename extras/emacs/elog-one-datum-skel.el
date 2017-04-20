;;; elog-one-datum-skel.el - single u32 datum elog skeleton

(require 'skeleton)

(define-skeleton skel-elog-one-datum
"Insert a skeleton single datum event definition"
nil
'(setq function-name (skeleton-read "Function: "))
'(setq label (skeleton-read "Label: "))

"

/* $$$ May or may not be needed */
#include <vlib/vlib.h>
#include <vppinfra/elog.h>

static inline void " function-name " (u32 data)
{
  ELOG_TYPE_DECLARE (e) = 
    {
      .format = \"" label ": %d\",
      .format_args = \"i4\",
    };
  
  elog (&vlib_global_main.elog_main, &e, data);
}

")
