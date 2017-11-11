
#ifndef SRC_VNET_DHCP_CLIENT6_H_
#define SRC_VNET_DHCP_CLIENT6_H_

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vnet/dhcp/dhcp6_packet.h>

#define DHCPV6_DUID_MAX_LEN 128

#define foreach_dhcp6_client_state               \
_(DHCP6_SOLICIT)                                 \
_(DHCP6_REQUEST)                                 \
_(DHCP6_BOUND)

typedef enum {
#define _(a) a,
  foreach_dhcp6_client_state
#undef _
} dhcp6_client_state_t;

typedef struct {
  /* The client interface */
  u32 sw_if_index;

  /* Current state */
  dhcp6_client_state_t state;

  /* Send next pkt at this time */
  f64 next_transmit;

  /* Current retransmission timer */
  f64 retransmission_timer;

  /* DHCP transaction ID, a random number */
  u32 transaction_id;

  /* vectors, consumed by dhcp client code */
  u8 duid[DHCPV6_DUID_MAX_LEN];
  u16 duid_length;

  /* rewrite information to send packet on interface */
  u8 * l2_rewrite;

  f64 transaction_start;

  /* Returned state */
  f64 last_state_time;
  dhcpv6_duid_t opt_server_duid;
  u8 *opt_server_duid_data;
  dhcpv6_ia_header_t opt_ia_pd;
  dhcpv6_ia_opt_pd_t opt_iaprefix;

} dhcp6_client_t;

typedef struct {
  /* DHCP client pool */
  dhcp6_client_t * clients;
  uword * client_by_sw_if_index;
  u32 seed;
} dhcp6_client_main_t;

extern dhcp6_client_main_t dhcp6_client_main;

typedef struct {
  int is_add;
  u32 sw_if_index;
  u8 duid[DHCPV6_DUID_MAX_LEN];
  u16 duid_length;
} dhcp6_client_add_del_args_t;

int dhcp6_client_add_del (dhcp6_client_add_del_args_t * a);

int dhcp6_client_for_us (vlib_main_t *, u32 buffer_index);

#endif /* SRC_VNET_DHCP_CLIENT6_H_ */
