
#ifndef _GPCAPNG_OUTPUT_H_
#define _GPCAPNG_OUTPUT_H_

/* Enum for destination types */
typedef enum
{
  PCAPNG_DEST_FILE = 0,
  PCAPNG_DEST_HTTP,
  PCAPNG_DEST_MAX
} pcapng_destination_type_t;

typedef u32 worker_dest_index_t;

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
  int (*write_pcapng_shb) (gpcapng_dest_t *out, void *ctx);
  int (*write_pcapng_idb) (gpcapng_dest_t *out, void *ctx, u32 if_index,
			   const char *if_name);
  int (*write_pcapng_epb) (gpcapng_dest_t *out, void *ctx, u32 if_index,
			   u64 timestamp, u32 orig_len, void *packet_data,
			   u32 packet_len);
  void (*print_worker_context) (vlib_main_t *vm, void *worker_ctx);
  /* Can be extended with additional methods */
} gpcapng_dest_t;

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
  if (!ctx) {
     // 0 is a valid ctx during the transient times, as it's allocated by a worker.
     return;
  }
  gpcapng_worker_context_common_t *cc = ctx;
  ALWAYS_ASSERT (cc->context_signature == CONTEXT_SIGNATURE);
  ALWAYS_ASSERT (cc->context_type <= 50);
}

u32 find_destination_by_name (const char *name);

u8 *get_pcapng_preamble_vec ();

void set_pcapng_output_file (gpcapng_dest_t *output);

void gpcapng_ensure_session_manager ();
void set_pcapng_output_http (gpcapng_dest_t *output);

/* Worker Destination Index (WDI): a combination of the worker index and
 * destination index */

always_inline worker_dest_index_t
make_wdi (u16 worker_index, u16 destination_index)
{
  return (((u32) worker_index << 16) + ((u32) destination_index));
}

always_inline u16
wdi_to_worker_index (worker_dest_index_t wdi)
{
  return (wdi >> 16);
}

always_inline u16
wdi_to_destination_index (worker_dest_index_t wdi)
{
  return (wdi & 0xffff);
}

void *wdi_to_worker_context (worker_dest_index_t wdi);
void wdi_set_ready_flag (worker_dest_index_t wdi, int is_ready);
gpcapng_dest_t *wdi_to_dest (worker_dest_index_t wdi);

#endif // _GPCAPNG_OUTPUT_H_
