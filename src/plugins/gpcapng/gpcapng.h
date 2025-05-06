#ifndef _GENEVE_PCAPNG_
#define _GENEVE_PCAPNG_


typedef struct gpcapng_main_t gpcapng_main_t;

gpcapng_main_t *get_gpcapng_main ();

#include "filter.h"
#include "destination.h"

typedef struct {
    worker_dest_index_t wdi;
    f64 expiry_time;
} retry_entry_t;

/* Plugin state */
struct gpcapng_main_t {
  /* API message ID base */
  u16 msg_id_base;

  /* Vector of registered option definitions */
  geneve_option_def_t *option_defs;
  
  /* Hash table: option_name -> index in option_defs */
  uword *option_by_name;
  
  /* Hash table: (class,type) -> index in option_defs */
  uword *option_by_class_type;
  
  /* Global filters */
  geneve_capture_filter_t *global_filters;
  
  /* Per-interface filter data */
  struct {
    u8 capture_enabled;              /* Whether capture is enabled on this interface */
    geneve_capture_filter_t *filters; /* Vector of active filters */
  } *per_interface;
  
  /* vector of configured outputs */
  gpcapng_dest_t *outputs;
  
  /* Per-worker vectors of output context pointers */
  void ***worker_output_ctx;

  /* Per-worker bitmaps indicating context readiness for given outputs */
  uword **worker_output_ctx_is_ready;

  /* Per-worker retry management */
  retry_entry_t **worker_retry_queue;  /* Vector per worker, sorted by expiry_time */
  
  /* Feature arc indices */
  u32 ip4_geneve_input_arc;
  u32 ip6_geneve_input_arc;
};


#endif


