#ifndef _GENEVE_PCAPNG_OUTPUT_H_
#define _GENEVE_PCAPNG_OUTPUT_H_

typedef struct geneve_output_t geneve_output_t;

/* Output interface definition for extensibility */
typedef struct geneve_output_t {
  void *(*init) (u32 worker_index);
  void (*cleanup) (void *ctx);
  int (*chunk_write) (void *ctx, const void *chunk, size_t chunk_size);
  void (*flush) (void *context);
  int (*write_pcapng_shb) (geneve_output_t *out, void *ctx);
  int (*write_pcapng_idb) (geneve_output_t *out, void *ctx, u32 if_index, const char *if_name);
  int (*write_pcapng_epb) (geneve_output_t *out, void *ctx, u32 if_index, u64 timestamp, 
                           u32 orig_len, void *packet_data, u32 packet_len);
  /* Can be extended with additional methods */
} geneve_output_t;

#endif // _GENEVE_PCAPNG_OUTPUT_H_
