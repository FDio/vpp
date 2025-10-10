#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/parser.h>
#include <vnet/sfdp/lookup/parser_inlines.h>
#include <vnet/sfdp/lookup/lookup_ip4.h>
#include <unittest/sfdp_test/unittest.h>
#include <unittest/unity/unity.h>

#define TEST_SRC_ADDRESS 0xC0A80001
#define TEST_DST_ADDRESS 0xC0A80002
#define TEST_SRC_PORT	 12345
#define TEST_DST_PORT	 80
SFDP_PARSER_REGISTER (test_parser_v4) = {
  .name = "test-parser-v4",
  .calc_key_fn = (void *) sfdp_calc_key_v4,
  .key_size = sizeof (sfdp_session_ip4_key_t),
  .proto_offset = offsetof (sfdp_session_ip4_key_t, ip4_key.proto),
  .type = SFDP_SESSION_TYPE_USER,
  .format_fn = {
    [SFDP_PARSER_FORMAT_FUNCTION_CONTEXT] = format_sfdp_ipv4_context_id,
    [SFDP_PARSER_FORMAT_FUNCTION_INGRESS] = format_sfdp_ipv4_ingress,
    [SFDP_PARSER_FORMAT_FUNCTION_EGRESS] = format_sfdp_ipv4_egress,
  },
  .normalize_key_fn = (void*) sfdp_normalise_ip4_key,
};
SFDP_PARSER_DEFINE_NODE (test_parser_v4);

#define TEST_ASSESS_ASSERT(cond, msg)                                         \
  if (!(cond))                                                                \
    {                                                                         \
      pkt->err = (msg);                                                       \
      return 0;                                                               \
    }
static u32
test_parser_v4_assess_fn (struct sfdp_unittest_pending_pkt_t_ *pkt,
			  void *test_data)
{
  // sfdp_unittest_main_t *um = &sfdp_unittest_main;
  vlib_buffer_t *b = vlib_get_buffer (vlib_get_main (), pkt->bi);
  u32 flow_index = b->flow_id;
  u32 session_index = sfdp_session_from_flow_index (flow_index);
  sfdp_session_t *session;
  sfdp_session_ip4_key_t nkey;
  session = sfdp_session_at_index (session_index);
  TEST_ASSESS_ASSERT (session->type == SFDP_SESSION_TYPE_USER,
		      "Wrong session type");
  TEST_ASSESS_ASSERT (
    session->parser_index[SFDP_SESSION_KEY_PRIMARY] ==
      sfdp_parser_registration_mutable_test_parser_v4.sfdp_parser_data_index,
    "Wrong parser index");
  TEST_ASSESS_ASSERT (session->key_flags ==
			SFDP_SESSION_KEY_FLAG_PRIMARY_VALID_USER,
		      "Wrong key flags");
  sfdp_normalise_ip4_key (session, &nkey, SFDP_SESSION_KEY_PRIMARY);
  TEST_ASSESS_ASSERT (nkey.ip4_key.proto == IP_PROTOCOL_TCP, "Wrong protocol");
  TEST_ASSESS_ASSERT (nkey.ip4_key.ip_addr_lo ==
			clib_net_to_host_u32 (TEST_SRC_ADDRESS),
		      "Wrong source address");
  TEST_ASSESS_ASSERT (nkey.ip4_key.ip_addr_hi ==
			clib_net_to_host_u32 (TEST_DST_ADDRESS),
		      "Wrong destination address");
  TEST_ASSESS_ASSERT (nkey.ip4_key.port_lo == TEST_SRC_PORT,
		      "Wrong source port");
  TEST_ASSESS_ASSERT (nkey.ip4_key.port_hi == TEST_DST_PORT,
		      "Wrong destination port");
  TEST_ASSESS_ASSERT (nkey.context_id == 0, "Wrong context id");
  TEST_ASSESS_ASSERT (session->state == SFDP_SESSION_STATE_FSOL,
		      "Wrong session state");
  return 1;
}
void
test_parser_v4_fn (void)
{
  /* Generate an IPv4 TCP packet buffer */
  u8 retries = 50;
  u32 bi;
  u32 *to_next;
  vlib_buffer_t *b;
  u8 *data;
  ip4_header_t *ip4;
  tcp_header_t *tcp;
  vlib_main_t *vm = vlib_get_main ();
  sfdp_unittest_main_t *um = &sfdp_unittest_main;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { 0 };
  vlib_frame_t *f;
  uword pending_pkt_idx;
  u32 *peeked_pending_pkt_idx;
  sfdp_unittest_pending_pkt_t *pending_pkt;
  sfdp_tenant_t *tenant;
  u16 tenant_idx;
  u32 node_index = test_parser_v4_node.index;
  // u32 node_index = sfdp_lookup_ip4_node.index;
  int res = vlib_buffer_alloc (vm, &bi, 1);
  TEST_ASSERT_EQUAL_INT (res, 1);

  b = vlib_get_buffer (vm, bi);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  b->current_length = 0;

  data = vlib_buffer_get_current (b);
  ip4 = (ip4_header_t *) data;
  ip4->ip_version_and_header_length = 0x45;
  ip4->tos = 0;
  ip4->length =
    clib_host_to_net_u16 (sizeof (ip4_header_t) + sizeof (tcp_header_t));
  ip4->fragment_id = 0;
  ip4->flags_and_fragment_offset = 0;
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_TCP;
  ip4->src_address.as_u32 = clib_host_to_net_u32 (TEST_SRC_ADDRESS);
  ip4->dst_address.as_u32 = clib_host_to_net_u32 (TEST_DST_ADDRESS);
  tcp = (tcp_header_t *) (data + sizeof (ip4_header_t));
  tcp->src_port = clib_host_to_net_u16 (TEST_SRC_PORT);
  tcp->dst_port = clib_host_to_net_u16 (TEST_DST_PORT);
  tcp->seq_number = clib_host_to_net_u32 (1);
  tcp->ack_number = clib_host_to_net_u32 (0);
  tcp->data_offset_and_reserved = 0x50;
  tcp->flags = TCP_FLAG_SYN;
  tcp->window = clib_host_to_net_u16 (65535);
  tcp->checksum = 0;
  tcp->urgent_pointer = 0;
  b->current_length = sizeof (ip4_header_t) + sizeof (tcp_header_t);

  /* Put the right tenant id and index */
  kv.key = 0;
  TEST_ASSERT_FALSE (
    clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv));
  tenant_idx = kv.value;
  tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
  b->flow_id = tenant->context_id;
  sfdp_buffer (b)->tenant_index = tenant_idx;
  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);

  sfdp_unittest_enqueue_pending_pkt (bi, test_parser_v4_assess_fn, NULL);

  while (--retries && (peeked_pending_pkt_idx =
			 clib_ring_deq (sfdp_unittest_main.handled_pkts)) == 0)
    {
      vlib_worker_thread_barrier_release (vm);
      vlib_process_suspend (vm, 1e-3);
      vlib_worker_thread_barrier_sync (vm);
    }
  TEST_ASSERT_TRUE (peeked_pending_pkt_idx != 0);
  pending_pkt_idx = peeked_pending_pkt_idx[0];
  pending_pkt = pool_elt_at_index (um->pending_pkts, pending_pkt_idx);
  TEST_ASSERT_TRUE (pending_pkt->bi == bi);
  TEST_ASSERT_MESSAGE (pending_pkt->success, pending_pkt->err);
  pool_put_index (um->pending_pkts, pending_pkt_idx);
}