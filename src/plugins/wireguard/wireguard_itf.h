#include <wireguard/wireguard_index_table.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_peer.h>

typedef struct wg_itf_t_
{
  int ii_user_instance;
  u32 ii_sw_if_index;

  // Interface params
  noise_local_t local;
  cookie_checker_t cookie_checker;
  u16 port;

  // Peers pool
  wg_peer_t *peers;
  wg_index_table_t index_table;

} __clib_packed wg_itf_t;


int wg_itf_create (u32 user_instance, u8 private_key_64[NOISE_KEY_LEN_BASE64],
                                 u16 port, u32 * sw_if_indexp);
int wg_itf_delete (u32 sw_if_index);
wg_itf_t* wg_itf_find_by_sw_if_index (u32 sw_if_index);
