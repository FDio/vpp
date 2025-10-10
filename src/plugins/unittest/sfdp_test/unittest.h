#ifndef __included_unittest_h__
#define __included_unittest_h__
#include <vppinfra/hash.h>
#include <vppinfra/ring.h>
#include <vppinfra/pool.h>
#include <vnet/sfdp/service.h>

#define SFDP_UNITTEST_MAX_PENDING_PKTS 1024

struct sfdp_unittest_pending_pkt_t_;

typedef u32 (*sfdp_unittest_pending_cb_t) (
  struct sfdp_unittest_pending_pkt_t_ *pkt, void *test_data);
typedef struct sfdp_unittest_pending_pkt_t_
{
  u32 bi;
  sfdp_unittest_pending_cb_t test_cb;
  void *test_data;
  u8 success;
  const char *err;
} sfdp_unittest_pending_pkt_t;

typedef struct
{
  sfdp_unittest_pending_cb_t test_cb; /* callback */
  ;
  sfdp_unittest_pending_pkt_t *pending_pkts; /* pool */
  uword *pending_pkts_by_bi;		     /* hash */
  u32 *handled_pkts;			     /* ring */
} sfdp_unittest_main_t;
extern sfdp_unittest_main_t sfdp_unittest_main;

static_always_inline uword
sfdp_unittest_enqueue_pending_pkt (u32 bi, sfdp_unittest_pending_cb_t test_cb,
				   void *test_data)
{
  sfdp_unittest_main_t *um = &sfdp_unittest_main;
  sfdp_unittest_pending_pkt_t *pending_pkt;
  uword pending_pkt_idx;

  pool_get (um->pending_pkts, pending_pkt);
  pending_pkt->bi = bi;
  pending_pkt->test_cb = test_cb;
  pending_pkt->test_data = test_data;
  pending_pkt->success = 0;

  pending_pkt_idx = pending_pkt - um->pending_pkts;
  hash_set (um->pending_pkts_by_bi, bi, pending_pkt_idx);
  return pending_pkt_idx;
}

SFDP_SERVICE_DECLARE (unittest);
SFDP_SERVICE_DECLARE (drop);
#endif /* __included_unittest_h__ */