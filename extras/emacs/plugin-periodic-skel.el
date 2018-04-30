;;; plugin-periodic-skel.el - periodic (process) node skeleton
;;;
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

(require 'skeleton)

(define-skeleton skel-plugin-periodic
"Insert a periodic node skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
'(setq capital-oh-en "ON")
"/*
 * " plugin-name "_periodic.c - skeleton plug-in periodic function 
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vppinfra/error.h>
#include <" plugin-name "/" plugin-name ".h>

static void 
handle_event1 (" plugin-name "_main_t *pm, f64 now, uword event_data)
{
  clib_warning (\"received " PLUGIN-NAME "_EVENT1\");
}
                           
static void 
handle_event2 (" plugin-name "_main_t *pm, f64 now, uword event_data)
{
  clib_warning (\"received " PLUGIN-NAME "_EVENT2\");
}
                           
static void
handle_periodic_enable_disable (" plugin-name"_main_t *pm, f64 now, uword event_data)
{
   clib_warning (\"Periodic timeouts now %s\", 
     event_data ? \"enabled\" : \"disabled\");
   pm->periodic_timer_enabled = event_data;
}

static void
handle_timeout (" plugin-name"_main_t *pm, f64 now)
{
  clib_warning (\"timeout at %.2f\", now);
}

static uword
" plugin-name "_periodic_process (vlib_main_t * vm,
	                  vlib_node_runtime_t * rt, vlib_frame_t * f)
{
  " plugin-name "_main_t *pm = &" plugin-name "_main;
  f64 now;
  f64 timeout = 10.0;
  uword *event_data = 0;
  uword event_type;
  int i;

  while (1)
    {
      if (pm->periodic_timer_enabled)
        vlib_process_wait_for_event_or_clock (vm, timeout);
      else
        vlib_process_wait_for_event (vm);

      now = vlib_time_now (vm);

      event_type = vlib_process_get_events (vm, (uword **) & event_data);

      switch (event_type)
	{
	  /* Handle " PLUGIN-NAME "_EVENT1 */
	case " PLUGIN-NAME "_EVENT1:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_event1 (pm, now, event_data[i]);
	  break;

	  /* Handle " PLUGIN-NAME "_EVENT2 */
	case " PLUGIN-NAME"_EVENT2:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_event2 (pm, now, event_data[i]);
	  break;
          /* Handle the periodic timer on/off event */
	case " PLUGIN-NAME"_EVENT_PERIODIC_ENABLE_DISABLE:
	  for (i = 0; i < vec_len (event_data); i++)
	    handle_periodic_enable_disable (pm, now, event_data[i]);
	  break;

          /* Handle periodic timeouts */
	case ~0:
	  handle_timeout (pm, now);
	  break;
	}
      vec_reset_length (event_data);
    }
  return 0;			/* or not */
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE ("plugin-name"_periodic_node) =
{
  .function = " plugin-name "_periodic_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = \"" plugin-name "-periodic-process\",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: " capital-oh-en "
 *
 * Local Variables:
 * eval: (c-set-style \"gnu\")
 * End:
 */
")
