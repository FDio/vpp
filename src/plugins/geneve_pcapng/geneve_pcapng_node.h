
typedef struct
{
  u64 elapsed;
  u32 sw_if_index;
  u32 dest_index;
} pcapng_capture_trace_t;

#define foreach_pcapng_capture_error                                              \
  _ (CAPTURED, "packets captured")                            \
  _ (MATCHED, "matched filter")                         \

typedef enum
{ 
#define _(sym, str) PCAPNG_CAPTURE_ERROR_##sym,
  foreach_pcapng_capture_error
#undef _
    PCAPNG_CAPTURE_N_ERROR,
} pcapng_capture_error_t;


