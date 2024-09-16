#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <pvti/pvti.h>
#include <pvti/pvti_if.h>

typedef struct
{
  u16 total_chunk_length;
} pvti_input_chunk_t;

#define MAX_CHUNKS 32

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  ip_address_t remote_ip;
  u16 remote_port;
  u16 local_port;
  u32 seq;
  pvti_input_chunk_t chunks[MAX_CHUNKS];
  u8 chunk_count;
  u8 trace_type;
  u8 packet_data[64];
} pvti_input_trace_t;

#define foreach_pvti_input_trace_type                                         \
  _ (drop, "drop")                                                            \
  _ (decap, "decapsulate")                                                    \
  _ (free, "free")                                                            \
  _ (enqueue, "enqueue")

typedef enum
{
#define _(f, s) PVTI_INPUT_TRACE_##f,
  foreach_pvti_input_trace_type
#undef _
    PVTI_INPUT_TRACE_N_TYPES,
} pvti_input_trace_type_t;

#define foreach_pvti_input_error                                              \
  _ (PROCESSED, "PVTI tunneled packets processed")                            \
  _ (DECAPSULATED, "PVTI inner packets decapsulated")                         \
  _ (PEER, "Could not find a peer")                                           \
  _ (NOCHUNKS, "Packet has no chunks")                                        \
  _ (NO_BUFFERS, "No buffers available to decapsulate")                       \
  _ (TOOMANYREASS, "Packet has more reassembly chunks than total")            \
  _ (PACKET_TOO_SHORT, "Packet too short")

typedef enum
{
#define _(sym, str) PVTI_INPUT_ERROR_##sym,
  foreach_pvti_input_error
#undef _
    PVTI_INPUT_N_ERROR,
} pvti_input_error_t;

typedef enum
{
  PVTI_INPUT_NEXT_DROP,
  PVTI_INPUT_NEXT_IP4_INPUT,
  PVTI_INPUT_NEXT_IP6_INPUT,
  PVTI_INPUT_NEXT_PUNT,
  PVTI_INPUT_N_NEXT,
} pvti_input_next_t;
