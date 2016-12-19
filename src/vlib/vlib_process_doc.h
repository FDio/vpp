/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#error do not #include this file!

/** \file

    Cooperative multi-tasking thread support.

    Vlib provides a lightweight cooperative multi-tasking thread
    model. Context switching costs a setjmp/longjump pair.  It's not
    unreasonable to put vlib threads to sleep for 10us.

    The graph node scheduler invokes these processes in much the same
    way as traditional vector-processing run-to-completion graph
    nodes; plus-or-minus a setjmp/longjmp pair required to switch
    stacks. Simply set the vlib_node_registration_t type field to
    VLIB_NODE_TYPE_PROCESS. Process is a misnomer; these are threads.

    As of this writing, the default stack size is 2<<15;
    32kb. Initialize the node registration's
    process_log2_n_stack_bytes member as needed. The graph node
    dispatcher makes some effort to detect stack overrun. We map a
    no-access page below each thread stack.

    Process node dispatch functions are expected to be while(1) { }
    loops which suspend when not otherwise occupied, and which must
    not run for unreasonably long periods of time.  Unreasonably long
    is an application-dependent concept. Over the years, we have
    constructed frame-size sensitive control-plane nodes which will
    use a much higher fraction of the available CPU bandwidth when the
    frame size is low. Classic example: modifying forwarding
    tables. So long as the table-builder leaves the forwarding tables
    in a valid state, one can suspend the table builder to avoid
    dropping packets as a result of control-plane activity.

    Process nodes can suspend for fixed amounts of time, or until another
    entity signals an event, or both. See the example below.

    When running in VLIB process context, one must pay strict attention to
    loop invariant issues. If one walks a data structure and calls a
    function which may suspend, one had best know by construction that it
    cannot change. Often, it s best to simply make a snapshot copy of a
    data structure, walk the copy at leisure, then free the copy.

    Here's an example:

    <code><pre>
    \#define EXAMPLE_POLL_PERIOD 10.0

    static uword
    example_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
                     vlib_frame_t * f)
    {
      f64 poll_time_remaining;
      uword event_type, *event_data = 0;

      poll_time_remaining = EXAMPLE_POLL_PERIOD;
      while (1)
        {
          int i;

           // Sleep until next periodic call due,
           // or until we receive event(s)
           //
          poll_time_remaining =
    	    vlib_process_wait_for_event_or_clock (vm, poll_time_remaining);

          event_type = vlib_process_get_events (vm, &event_data);
          switch (event_type)
     	    {
       	    case ~0:		// no events => timeout
      	      break;

            case EVENT1:
    	      for (i = 0; i < vec_len (event_data); i++)
    	        handle_event1 (mm, event_data[i]);
    	      break;

    	    case EVENT2:
    	      for (i = 0; i < vec_len (event_data); i++)
    	        handle_event2 (vm, event_data[i]);
    	      break;

              // ... and so forth for each event type

            default:
              // This should never happen...
    	      clib_warning ("BUG: unhandled event type %d",
                            event_type);
    	      break;
      	    }
          vec_reset_length (event_data);

          // Timer expired, call periodic function
          if (vlib_process_suspend_time_is_zero (poll_time_remaining))
    	    {
    	      example_periodic (vm);
    	      poll_time_remaining = EXAMPLE_POLL_PERIOD;
    	    }
        }
      // NOTREACHED
      return 0;
    }

    static VLIB_REGISTER_NODE (example_node) = {
      .function = example_process,
      .type = VLIB_NODE_TYPE_PROCESS,
      .name = "example-process",
    };
    </pre></code>

    In this example, the VLIB process node waits for an event to
    occur, or for 10 seconds to elapse. The code demuxes on the event
    type, calling the appropriate handler function.

    Each call to vlib_process_get_events returns a vector of
    per-event-type data passed to successive vlib_process_signal_event
    calls; vec_len (event_data) >= 1.  It is an error to process only
    event_data[0].

    Resetting the event_data vector-length to 0 by calling
    vec_reset_length (event_data) - instead of calling vec_free (...)
    - means that the event scheme doesn t burn cycles continuously
    allocating and freeing the event data vector. This is a common
    coding pattern, well worth using when appropriate.
*/

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
