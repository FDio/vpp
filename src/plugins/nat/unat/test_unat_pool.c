#include <assert.h>
#include <vnet/ip/ip.h>
#include <arpa/inet.h>
#include "pool.h"
#include "unat.h"
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>
//#include "tscmarks.h"

unat_session_t *sessions;
clib_bihash_16_8_t in2out_hash;
clib_bihash_16_8_t out2in_hash;

u8 *format_ip4_address (u8 * s, va_list * args) { return 0; }

static void
test_create (void)
{
  ip4_address_t a;
  u32 poolindex;
  a.as_u32 = 0x01020304;
  poolindex = pool_add_addr_pool(&a, 24, 0, 0, 0, 0);
  assert(poolindex == 0);

  poolindex = pool_add_addr_pool(&a, 32, 8, 0, 0, 0);
  assert(poolindex == 1);

  poolindex = pool_add_addr_pool(&a, 32, 8, 1, 0, 0);
  assert(poolindex == 2);

  unat_pool_t *p = unat_pool_get(1);
  assert(p->prefix.as_u32 == a.as_u32);
  assert(p->psid_length == 8);

}

static int
l3_checksum_delta (unat_instructions_t instructions,
                   ip4_address_t *pre_sa, ip4_address_t *post_sa,
		   ip4_address_t *pre_da, ip4_address_t *post_da)
{
  ip_csum_t c = 0;
  if (instructions & UNAT_INSTR_SOURCE_ADDRESS) {
    c = ip_csum_add_even(c, post_sa->as_u32);
    c = ip_csum_sub_even(c, pre_sa->as_u32);
  }
  if (instructions & UNAT_INSTR_DESTINATION_ADDRESS) {
    c = ip_csum_sub_even(c, pre_da->as_u32);
    c = ip_csum_add_even(c, post_da->as_u32);
  }
  return c;
}

/*
 * L4 checksum delta (UDP/TCP)
 */
static int
l4_checksum_delta (unat_instructions_t instructions, ip_csum_t c,
                   u16 pre_sp, u16 post_sp, u16 pre_dp, u16 post_dp)
{
  if (instructions & UNAT_INSTR_SOURCE_PORT) {
    c = ip_csum_add_even(c, post_sp);
    c = ip_csum_sub_even(c, pre_sp);
  }
  if (instructions & UNAT_INSTR_DESTINATION_PORT) {
    c = ip_csum_add_even(c, post_dp);
    c = ip_csum_sub_even(c, pre_dp);
  }
  return c;
}

static bool
unat_session_exists (clib_bihash_16_8_t *h, unat_key_t *k)
{
  clib_bihash_kv_16_8_t value;

  if (clib_bihash_search_16_8 (h, (clib_bihash_kv_16_8_t *)k, &value)) {
    return false;
  }
  return true;
}

/*
 * Address and port allocation algorithm
 * - Pick an address from the outside pool modulo the inside source address
 *   This is to achieve some level of load balancing across the pool.
 * - Pick the same outside port and the inside port if possible
 * - If conflict, i.e. there is already a session X':x' -> Y:y,
 *   try the next port.
 * - If this fails more than 10 times, give up.
 * Port in host endian
 */
static u16
get_port (unat_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port;
  }
  return (port & ~p->psid_mask) | p->psid;
}

/*
 * Assuming psid_offset = 0
 */
static u16
get_next_port (unat_pool_t *p, u16 port)
{
  if (p->psid_length == 0) {
    return port <= 0xFFFF - 1 ? port + 1 : 1025;
  }
  return get_port(p, port <= p->psid_mask - 1 ? port + 1 : 1025);
}

static int
unat_allocate_address_and_port (u32 thread_index, u32 vrf_id, u8 proto,
				ip4_address_t X, u16 x,
				ip4_address_t Y, u16 y,
				ip4_address_t *X_marked, u16 *x_marked)
{
  unat_pool_t *p = unat_pool_get(0);
  u32 address;
  u16 port = get_port(p, ntohs(x));
  int i = 0;

  address = ntohl(p->prefix.as_u32) | (ntohl(X.as_u32) % p->count);
  X_marked->as_u32 = htonl(address);

  while (1) {
    unat_key_t kv = { .sa.as_u32 = Y.as_u32,
		      .da.as_u32 = X_marked->as_u32,
		      .proto = proto,
		      .fib_index = vrf_id,
		      .sp = y,
		      .dp = htons(port) };

    if (unat_session_exists(&out2in_hash, &kv)) {
      if (++i > 10)
	return -1;
      port = get_next_port(p, port);
      continue;
    }
    *x_marked = htons(port);
    return 0;
  }
}

static void
unat_fp_session_create (unat_fp_session_t *fs, unat_key_t *k,
			unat_instructions_t instructions,
			u32 fib_index, ip4_address_t *post_sa, ip4_address_t *post_da,
			u16 post_sp, u16 post_dp, ip_csum_t checksum, ip_csum_t l4_checksum,
			u16 tcp_mss, enum unat_session_state state)
{
  fs->k.as_u64[0] = k->as_u64[0];
  fs->k.as_u64[1] = k->as_u64[1];
  fs->instructions = instructions;
  fs->fib_index = fib_index;
  fs->post_sa.as_u32 = post_sa ? post_sa->as_u32 : 0;
  fs->post_da.as_u32 = post_da ? post_da->as_u32 : 0;
  fs->post_sp = post_sp;
  fs->post_dp = post_dp;
  fs->checksum = checksum;
  fs->l4_checksum = l4_checksum;
  fs->tcp_mss = tcp_mss;
  fs->state = state;
}

static void
test_slownode (ip4_address_t src_address, ip4_address_t dst_address, u8 protocol, u16 sport, u16 dport)
{
  u32 thread_index = 0;
  f64 now = 0;
  u32 rx_fib_index0 = 0;

  /* Allocate external address and port */
  ip4_address_t X_marked;
  u16 x_marked;

  enum unat_session_state state0 = UNAT_STATE_UNKNOWN;
  bool has_ports0 = protocol == IP_PROTOCOL_TCP ||
    protocol == IP_PROTOCOL_UDP ? true : false;
  //tsc_mark("allocate address");
  int rv = unat_allocate_address_and_port(thread_index,
					  rx_fib_index0, protocol,
					  src_address, sport,
					  dst_address, dport,
					  &X_marked, &x_marked);
  assert(rv == 0);

  /* Create FP sessions (in2out, out2in) */
  ip_csum_t l4_c0 = 0;
  unat_instructions_t in2out_instr, out2in_instr;

  /* in2out session */
  //tsc_mark("create keys");
  in2out_instr = UNAT_INSTR_SOURCE_ADDRESS;
  unat_key_t in2out_kv0 = { .sa.as_u32 = src_address.as_u32,
			    .da.as_u32 = dst_address.as_u32,
			    .proto = protocol,
			    .fib_index = rx_fib_index0,
			    .sp = sport,
			    .dp = dport };

  /* out2in session */
  unat_key_t out2in_kv0 = { .sa.as_u32 = dst_address.as_u32,
			    .da.as_u32 = X_marked.as_u32,
			    .proto = protocol,
			    .fib_index = rx_fib_index0,
			    .sp = dport,
			    .dp = x_marked };

  unat_session_t *s;

  pool_get(sessions, s);
  u32 pool_index = s - sessions;
  //tsc_mark("checksum");
  ip_csum_t c0 = l3_checksum_delta(in2out_instr, &src_address, &X_marked, 0, 0);
  if (has_ports0) {
    in2out_instr |= UNAT_INSTR_SOURCE_PORT | UNAT_INSTR_TCP_CONN_TRACK;
    l4_c0 = l4_checksum_delta(in2out_instr, c0, sport, x_marked, 0, 0);
  }
  unat_fp_session_create(&s->in2out, &in2out_kv0, in2out_instr,
			 rx_fib_index0, &X_marked, 0, x_marked, 0,
			 c0, l4_c0, 0, state0);

  out2in_instr = UNAT_INSTR_DESTINATION_ADDRESS;
  c0 = l3_checksum_delta(out2in_instr, 0, 0, &X_marked, &src_address);
  if (has_ports0) {
    out2in_instr |= UNAT_INSTR_DESTINATION_PORT | UNAT_INSTR_TCP_CONN_TRACK;
    l4_c0 = l4_checksum_delta(out2in_instr, c0, 0, 0, x_marked, sport);
  }
  unat_fp_session_create(&s->out2in, &out2in_kv0, out2in_instr,
			 rx_fib_index0, 0, &src_address, 0, sport,
			 c0, l4_c0, 0, UNAT_STATE_UNKNOWN);

  s->last_heard = now;

  //tsc_mark("add to hash");
  clib_bihash_kv_16_8_t kv;
  kv.key[0]  = in2out_kv0.as_u64[0];
  kv.key[1]  = in2out_kv0.as_u64[1];
  kv.value = ((u64)thread_index << 32) | pool_index;
  if (clib_bihash_add_del_16_8 (&in2out_hash, &kv, 1)) {
    clib_warning("bihash add failed");
    // XXX: delete pool if hash fails
  }

  kv.key[0]  = out2in_kv0.as_u64[0];
  kv.key[1]  = out2in_kv0.as_u64[1];
  kv.value = ((u64)thread_index << 32) | pool_index;
  if (clib_bihash_add_del_16_8 (&out2in_hash, &kv, 1)) {
    clib_warning("bihash add failed");
    // XXX: delete pool if hash fails
  }
}

u32 max_sessions = 100000000;
int main (int arcg, char **argv)
{
  int i, count;
  clib_mem_init (0, 3ULL << 30);

  clib_bihash_init_16_8 (&in2out_hash, "in2out hash", max_sessions, max_sessions*250);
  clib_bihash_init_16_8 (&out2in_hash, "out2in hash", max_sessions, max_sessions*250);
  test_create();
  printf("Sizeof session: %lu\n", sizeof(unat_session_t));
  ip4_address_t src_address = {0}, dst_address = {0};
  u16 sport = 0, dport = 0;

  src_address.as_u32 = htonl(0x01020304);
  dst_address.as_u32 = htonl(0x01000000);
  sport = htons(80);
  dport = htons(53);

  count = 250;
  pool_init_fixed(sessions, max_sessions);
  while (1) {
    //tsc_mark("start");
    for (i = 0; i < count; i++) {
      dst_address.as_u32++;
      test_slownode (src_address, dst_address, IP_PROTOCOL_TCP, sport, dport);
    }
    //tsc_mark("end");
    //tsc_print(3, count);
  }

  assert(pool_elts(sessions) == count);
  clib_warning ("out2in: %U", format_bihash_16_8, &out2in_hash, 0);
}
