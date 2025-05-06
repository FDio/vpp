#ifndef _GENEVE_PCAPNG_
#define _GENEVE_PCAPNG_

typedef struct gpcapng_main_t gpcapng_main_t;

gpcapng_main_t *get_gpcapng_main ();

#include "destination.h"
#include "gpcapng_node.h"

/* No longer need per-interface structure - using bitmap instead */

typedef struct
{
  worker_dest_index_t wdi;
  f64 expiry_time;
} retry_entry_t;

/* Plugin state */
struct gpcapng_main_t
{
  /* API message ID base */
  u16 msg_id_base;

  /* Bitmap of interfaces with capture enabled */
  uword *capture_enabled_bitmap;

  /* vector of configured outputs */
  gpcapng_dest_t *outputs;

  /* Per-worker vectors of output context pointers */
  void ***worker_output_ctx;

  /* Per-worker bitmaps indicating context readiness for given outputs */
  uword **worker_output_ctx_is_ready;

  /* Per-worker retry management */
  retry_entry_t *
    *worker_retry_queue; /* Vector per worker, sorted by expiry_time */

  /* HTTP retry process management */
  u32 http_retry_process_node_index; /* 0 = not started, non-zero = started */
  u8 http_destinations_configured; /* 1 = HTTP destinations exist, 0 = none */

  /* Feature arc indices */
  u32 ip4_geneve_input_arc;
  u32 ip6_geneve_input_arc;

  /* Per-worker structures for two-pass processing */
  gpcapng_per_worker_t *per_worker;
};

/* API functions for external access */
uword *gpcapng_get_capture_enabled_bitmap (void);
int gpcapng_set_interface_capture (u32 sw_if_index, u8 enable);

#endif
