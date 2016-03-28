;;; elog-4-int-skel.el - 4 integer elog skeleton

(require 'skeleton)

(define-skeleton skel-elog-4-int-track
"Insert a skeleton 4-integer-with-track event definition"
nil
'(setq function-name (skeleton-read "Function: "))
'(setq track-label (skeleton-read "Track Label: "))
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
  ELOG_TRACK(" track-label ");
  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, " track-label ");
  ed->data[0] = data[0];
  ed->data[1] = data[1];
  ed->data[2] = data[2];
  ed->data[3] = data[3];
}

")
