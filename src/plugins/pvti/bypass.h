#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pvti/pvti.h>
#include <pvti/pvti_if.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 seq;
} pvti_bypass_trace_t;

#define foreach_pvti_bypass_error                                             \
  _ (PROCESSED, "PVTI bypass tunnel packets processed")

typedef enum
{
#define _(sym, str) PVTI_BYPASS_ERROR_##sym,
  foreach_pvti_bypass_error
#undef _
    PVTI_BYPASS_N_ERROR,
} pvti_bypass_error_t;

typedef enum
{
  PVTI_BYPASS_NEXT_DROP,
  PVTI_BYPASS_NEXT_PVTI_INPUT,
  PVTI_BYPASS_N_NEXT,
} pvti_bypass_next_t;
