;;; pipe-skel.el - pipelined graph node skeleton

(require 'skeleton)

(define-skeleton skel-periodic
"Insert a skeleton periodic process node"
nil
'(setq node-name (skeleton-read "Name: "))
'(setq uc-node-name (upcase node-name))
'(setq poll-period (skeleton-read "Poll period (f64 seconds, e.g. 10.0): "))

"
#define " uc-node-name "_POLL_PERIOD " poll-period "

static uword
" node-name "_process (vlib_main_t * vm,
                       vlib_node_runtime_t * rt,
                       vlib_frame_t * f)
{
    f64 poll_time_remaining;
    uword event_type, * event_data = 0;

    poll_time_remaining = " uc-node-name "_POLL_PERIOD;
    while (1) {
        int i;

        /* 
         * Sleep until next periodic call due, or until we receive event(s) 
         */
        poll_time_remaining = 
            vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);
        
        event_type = vlib_process_get_events (vm, &event_data);
        switch (event_type) {
        case ~0:                /* no events => timeout */
            break;

        /* 
         * $$$$ FIXME: add cases / handlers for each event type 
         */
        case EVENT1:
            for (i = 0; i < vec_len (event_data); i++) 
                handle_event1 (mm, event_data[i]);
            break;

        case EVENT2:
            for (i = 0; i < vec_len (event_data); i++) 
                handle_event2 (vm, event_data[i]);
	    break;

        /* ... and so forth for each event type */

        default:
            /* This should never happen... */
            clib_warning (\"BUG: unhandled event type %d\", event_type);
            break;
        }
        if (event_data)
            _vec_len (event_data) = 0;

        /* Timer expired, call periodic function */
        if (vlib_process_suspend_time_is_zero (poll_time_remaining)) {
            " node-name "_periodic (vm);
            poll_time_remaining = " uc-node-name "_POLL_PERIOD;
        }
    }

    return 0;
}

/*
 * " node-name " periodic node declaration 
 */
static VLIB_REGISTER_NODE (" node-name "_node) = {
    .function = " node-name "_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = \"" node-name "-process\",
};

/*
 * To signal an event:
 *
 * vlib_process_signal_event (vm, " node-name "_node.index, EVENTn, datum);
 *
 */
")
