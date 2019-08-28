/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020, LabN Consulting, L.L.C
 * March 2 2020, Christian E. Hopps <chopps@labn.net>
 */
#include <vppinfra/time.h>

typedef void (*deferred_callback_t) (void *data);

typedef struct deferred
{
  deferred_callback_t callback;
  void *data;
  f64 end;
} deferred_t;

#define foreach_deferred_event_type                                                                \
  _ (DEFERRED_EVENT_TYPE_BOGUS, "bogus-event")                                                     \
  _ (DEFERRED_EVENT_TYPE_SCHEDULE, "schedule")

typedef enum
{
#define _(n, s) n,
  foreach_deferred_event_type
#undef _
    DEFERRED_EVENT_N_TYPES
} deferred_event_type_t;

extern char *deferred_event_type_strings[DEFERRED_EVENT_N_TYPES];

extern vlib_node_registration_t deferred_process_node;

static inline void
defer (vlib_main_t *vm, deferred_callback_t callback, void *data, f64 delay)
{
  deferred_t *deferred = vec_new (deferred_t, 1);
  deferred->callback = callback;
  deferred->data = data;
  deferred->end = vlib_time_now (vm) + delay;
  clib_warning ("%s: Signalling deferred process: 0x%wx", __FUNCTION__, (uword) deferred);
  vlib_process_signal_event_mt (vm, deferred_process_node.index, DEFERRED_EVENT_TYPE_SCHEDULE,
				(uword) deferred);
}
