
#ifndef _GPCAPNG_NODE_H_
#define _GPCAPNG_NODE_H_

typedef struct
{
  u64 elapsed;
  u32 sw_if_index;
  u32 dest_index;
} pcapng_capture_trace_t;

/* Per-worker structure for two-pass packet processing */
typedef struct
{
  /* Buffer indices and corresponding destination indices */
  u32 *buffer_indices;
  u32 *dest_indices;
  vlib_buffer_t **bufs;

  /* Current frame size */
  u32 n_vectors;
} gpcapng_per_worker_t;

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
