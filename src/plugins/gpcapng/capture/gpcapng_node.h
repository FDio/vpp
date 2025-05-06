
#ifndef _GPCAPNG_NODE_H_
#define _GPCAPNG_NODE_H_

typedef struct
{
  u64 filtering_elapsed;
  u32 sw_if_index;
  u32 dest_index;
  char *filter_name; /* not owned: pointer to a string owned by filter! */
} pcapng_capture_trace_t;

/* gpcapng_per_worker_t is now defined in gpcapng.h */

#define foreach_pcapng_capture_error                                          \
  _ (CAPTURED, "packets for capture destination")                             \
  _ (MATCHED, "matched filter")                                               \
  _ (DROPPED, "dropped by destination")                                       \
  _ (NOT_READY, "destination not ready")

typedef enum
{
#define _(sym, str) PCAPNG_CAPTURE_ERROR_##sym,
  foreach_pcapng_capture_error
#undef _
    PCAPNG_CAPTURE_N_ERROR,
} pcapng_capture_error_t;

#endif /* _GPCAPNG_NODE_H_ */
