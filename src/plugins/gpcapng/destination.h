
#ifndef _GPCAPNG_OUTPUT_H_
#define _GPCAPNG_OUTPUT_H_

typedef struct gpcapng_dest_t gpcapng_dest_t;

/* Output interface definition for extensibility */
typedef struct gpcapng_dest_t {
  void *(*init) (u32 worker_index);
  void (*cleanup) (void *ctx);
  int (*chunk_write) (void *ctx, const void *chunk, size_t chunk_size);
  void (*flush) (void *context);
  int (*write_pcapng_shb) (gpcapng_dest_t *out, void *ctx);
  int (*write_pcapng_idb) (gpcapng_dest_t *out, void *ctx, u32 if_index, const char *if_name);
  int (*write_pcapng_epb) (gpcapng_dest_t *out, void *ctx, u32 if_index, u64 timestamp, 
                           u32 orig_len, void *packet_data, u32 packet_len);
  /* Can be extended with additional methods */
} gpcapng_dest_t;

void set_pcapng_output_file(gpcapng_dest_t *output);
void set_pcapng_output_gzip(gpcapng_dest_t *output);
void set_pcapng_output_igzip(gpcapng_dest_t *output);

void gpcapng_ensure_session_manager();
void set_pcapng_output_http(gpcapng_dest_t *output);


#endif // _GPCAPNG_OUTPUT_H_
