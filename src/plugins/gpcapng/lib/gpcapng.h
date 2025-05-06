#ifndef _GENEVE_PCAPNG_
#define _GENEVE_PCAPNG_

typedef struct gpcapng_main_t gpcapng_main_t;

gpcapng_main_t *get_gpcapng_main ();

/* Forward declarations and common types */
typedef u32 worker_dest_index_t;

/* Enum for destination types */
typedef enum
{
  PCAPNG_DEST_FILE = 0,
  PCAPNG_DEST_HTTP,
  PCAPNG_DEST_MAX
} pcapng_destination_type_t;

typedef struct gpcapng_dest_t gpcapng_dest_t;

/* Output interface definition for extensibility */
typedef struct gpcapng_dest_t
{
  char *name;
  void *arg;
  void *(*init) (gpcapng_dest_t *output, u16 worker_index,
		 u16 destination_index);
  void (*cleanup) (void *ctx);
  int (*chunk_write) (void *ctx, const void *chunk, size_t chunk_size);
  void (*flush) (void *context);
  void (*print_worker_context) (vlib_main_t *vm, void *worker_ctx);
  /* Can be extended with additional methods */
} gpcapng_dest_t;

/* Per-worker structure for two-pass packet processing */
typedef struct
{
  /* Buffer indices corresponding destination indices */
  u32 *buffer_indices;
  u32 *dest_indices;
  vlib_buffer_t **bufs;
  u64 *filtering_elapsed;

  /* Current frame size */
  u32 n_vectors;
} gpcapng_per_worker_t;

/* Common worker context structure used by all destinations */
typedef struct _gpcapng_worker_context_common_t
{
  uword packet_counter;
  uword last_sent_packet_counter;
  uword last_batch_sent_packet_counter;
  u8 *buffer_vec;
  pcapng_destination_type_t context_type;
  uword context_signature;
} gpcapng_worker_context_common_t;

#define CONTEXT_SIGNATURE 0xca917777
#define WDI_POISON_VALUE  0xcacacaca

always_inline void
worker_context_init_common (void *ctx, pcapng_destination_type_t type)
{
  gpcapng_worker_context_common_t *cc = ctx;
  cc->context_signature = CONTEXT_SIGNATURE;
  cc->context_type = type;
}

always_inline void
worker_context_verify (void *ctx)
{
  if (!ctx)
    {
      // 0 is a valid ctx during the transient times, as it's allocated by a
      // worker.
      return;
    }
  gpcapng_worker_context_common_t *cc = ctx;
  ALWAYS_ASSERT (cc->context_signature == CONTEXT_SIGNATURE);
  ALWAYS_ASSERT (cc->context_type <= 50);
}

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

/* API functions for external access are provided through the plugin vtable */
int gpcapng_set_interface_capture (u32 sw_if_index, u8 enable);

#endif
