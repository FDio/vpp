/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/mpls/mpls_types.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_signal.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_test.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/mpls_fib.h>

#include <vnet/dpo/replicate_dpo.h>
#include <vnet/adj/adj_mcast.h>

#define MFIB_TEST_I(_cond, _comment, _args...)			\
({								\
    int _evald = (_cond);					\
    if (!(_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
        res = 1;                                                \
    } else {							\
        fformat(stderr, "PASS:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
    }								\
    res;							\
})
#define MFIB_TEST(_cond, _comment, _args...)			\
{								\
    if (MFIB_TEST_I(_cond, _comment, ##_args)) {		\
        return 1;                                               \
        ASSERT(!("FAIL: " _comment));				\
    }								\
}
#define MFIB_TEST_NS(_cond)                                     \
{								\
    if (MFIB_TEST_I(_cond, "")) {                               \
        return 1;                                               \
        ASSERT(!("FAIL: "));                                    \
    }								\
}

/**
 * A 'i'm not fussed is this is not efficient' store of test data
 */
typedef struct test_main_t_ {
    /**
     * HW if indicies
     */
    u32 hw_if_indicies[4];
    /**
     * HW interfaces
     */
    vnet_hw_interface_t * hw[4];

} test_main_t;
static test_main_t test_main;

/* fake ethernet device class, distinct from "fake-ethX" */
static u8 * format_test_interface_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "test-eth%d", dev_instance);
}

static uword dummy_interface_tx (vlib_main_t * vm,
                                 vlib_node_runtime_t * node,
                                 vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}

static clib_error_t *
test_interface_admin_up_down (vnet_main_t * vnm,
                              u32 hw_if_index,
                              u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);
  return 0;
}

VNET_DEVICE_CLASS (test_interface_device_class,static) = {
  .name = "Test interface",
  .format_device_name = format_test_interface_name,
  .tx_function = dummy_interface_tx,
  .admin_up_down_function = test_interface_admin_up_down,
};

static u8 *hw_address;

static int
mfib_test_mk_intf (u32 ninterfaces)
{
    clib_error_t * error = NULL;
    test_main_t *tm = &test_main;
    u8 byte;
    int res;
    u32 i;

    res = 0;
    ASSERT(ninterfaces <= ARRAY_LEN(tm->hw_if_indicies));

    for (i=0; i<6; i++)
    {
        byte = 0xd0+i;
        vec_add1(hw_address, byte);
    }

    for (i = 0; i < ninterfaces; i++)
    {
        hw_address[5] = i;

        error = ethernet_register_interface(vnet_get_main(),
                                            test_interface_device_class.index,
                                            i /* instance */,
                                            hw_address,
                                            &tm->hw_if_indicies[i],
                                            /* flag change */ 0);

        MFIB_TEST((NULL == error), "ADD interface %d", i);

        error = vnet_hw_interface_set_flags(vnet_get_main(),
                                            tm->hw_if_indicies[i],
                                            VNET_HW_INTERFACE_FLAG_LINK_UP);
        tm->hw[i] = vnet_get_hw_interface(vnet_get_main(),
                                          tm->hw_if_indicies[i]);
        vec_validate (ip4_main.fib_index_by_sw_if_index,
                      tm->hw[i]->sw_if_index);
        vec_validate (ip6_main.fib_index_by_sw_if_index,
                      tm->hw[i]->sw_if_index);
        ip4_main.fib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;
        ip6_main.fib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;

        vec_validate (ip4_main.mfib_index_by_sw_if_index,
                      tm->hw[i]->sw_if_index);
        vec_validate (ip6_main.mfib_index_by_sw_if_index,
                      tm->hw[i]->sw_if_index);
        ip4_main.mfib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;
        ip6_main.mfib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;

        error = vnet_sw_interface_set_flags(vnet_get_main(),
                                            tm->hw[i]->sw_if_index,
                                            VNET_SW_INTERFACE_FLAG_ADMIN_UP);
        MFIB_TEST((NULL == error), "UP interface %d", i);
    }
    /*
     * re-eval after the inevitable realloc
     */
    for (i = 0; i < ninterfaces; i++)
    {
        tm->hw[i] = vnet_get_hw_interface(vnet_get_main(),
                                          tm->hw_if_indicies[i]);
    }

    return (res);
}

#define MFIB_TEST_REP(_cond, _comment, _args...)		\
{								\
    if (MFIB_TEST_I(_cond, _comment, ##_args)) {		\
        return (1);						\
    }								\
}

static int
mfib_test_validate_rep_v (const replicate_t *rep,
                          u16 n_buckets,
                          va_list *ap)
{
    const dpo_id_t *dpo;
    adj_index_t ai;
    dpo_type_t dt;
    int bucket;
    int res;

    res = 0;
    MFIB_TEST_REP((n_buckets == rep->rep_n_buckets),
                  "n_buckets = %d", rep->rep_n_buckets);

    for (bucket = 0; bucket < n_buckets; bucket++)
    {
        dt = va_arg(*ap, int);  // type promotion
        ai = va_arg(*ap, adj_index_t);
        dpo = replicate_get_bucket_i(rep, bucket);

        MFIB_TEST_REP((dt == dpo->dpoi_type),
                      "bucket %d stacks on %U",
                      bucket,
                      format_dpo_type, dpo->dpoi_type);

        if (DPO_RECEIVE != dt)
        {
            MFIB_TEST_REP((ai == dpo->dpoi_index),
                          "bucket %d [exp:%d] stacks on %U",
                          bucket, ai,
                          format_dpo_id, dpo, 0);
        }
    }
    return (res);
}

static int
mfib_test_entry (fib_node_index_t fei,
                 mfib_entry_flags_t eflags,
                 int n_buckets,
                 ...)
{
    const mfib_entry_t *mfe;
    const replicate_t *rep;
    mfib_prefix_t pfx;
    va_list ap;
    int res;

    va_start(ap, n_buckets);

    res = 0;
    mfe = mfib_entry_get(fei);
    mfib_entry_get_prefix(fei, &pfx);

    MFIB_TEST_REP((eflags == mfe->mfe_flags),
                  "%U has %U expect %U",
                  format_mfib_prefix, &pfx,
                  format_mfib_entry_flags, mfe->mfe_flags,
                  format_mfib_entry_flags, eflags);

    if (0 == n_buckets)
    {
        MFIB_TEST_REP((DPO_DROP == mfe->mfe_rep.dpoi_type),
                      "%U links to %U",
                      format_mfib_prefix, &pfx,
                      format_dpo_id, &mfe->mfe_rep, 0);
    }
    else
    {
        dpo_id_t tmp = DPO_INVALID;

        mfib_entry_contribute_forwarding(
            fei,
            fib_forw_chain_type_from_fib_proto(pfx.fp_proto),
            &tmp);
        rep = replicate_get(tmp.dpoi_index);

        MFIB_TEST_REP((DPO_REPLICATE == tmp.dpoi_type),
                      "%U links to %U",
                      format_mfib_prefix, &pfx,
                      format_dpo_type, tmp.dpoi_type);

        res = mfib_test_validate_rep_v(rep, n_buckets, &ap);

        dpo_reset(&tmp);
    }

    va_end(ap);

    return (res);
}

static int
mfib_test_entry_itf (fib_node_index_t fei,
                     u32 sw_if_index,
                     mfib_itf_flags_t flags)
{
    const mfib_entry_t *mfe;
    const mfib_itf_t *mfi;
    mfib_prefix_t pfx;
    int res;

    res = 0;
    mfe = mfib_entry_get(fei);
    mfi = mfib_entry_get_itf(mfe, sw_if_index);
    mfib_entry_get_prefix(fei, &pfx);

    MFIB_TEST_REP((NULL != mfi),
                  "%U has interface %d",
                  format_mfib_prefix, &pfx, sw_if_index);

    MFIB_TEST_REP((flags == mfi->mfi_flags),
                  "%U interface %d has flags %U expect %U",
                  format_mfib_prefix, &pfx, sw_if_index,
                  format_mfib_itf_flags, flags,
                  format_mfib_itf_flags, mfi->mfi_flags);

    return (res);
}

static int
mfib_test_entry_no_itf (fib_node_index_t fei,
                        u32 sw_if_index)
{
    const mfib_entry_t *mfe;
    const mfib_itf_t *mfi;
    mfib_prefix_t pfx;
    int res;

    res = 0;
    mfe = mfib_entry_get(fei);
    mfi = mfib_entry_get_itf(mfe, sw_if_index);
    mfib_entry_get_prefix(fei, &pfx);

    MFIB_TEST_REP((NULL == mfi),
                  "%U has no interface %d",
                  format_mfib_prefix, &pfx, sw_if_index);

    return (res);
}

static int
mfib_test_i (fib_protocol_t PROTO,
             vnet_link_t LINKT,
             const mfib_prefix_t *pfx_no_forward,
             const mfib_prefix_t *pfx_s_g,
             const mfib_prefix_t *pfx_star_g_1,
             const mfib_prefix_t *pfx_star_g_2,
             const mfib_prefix_t *pfx_star_g_3,
             const mfib_prefix_t *pfx_star_g_slash_m,
             const fib_prefix_t *pfx_itf,
             const ip46_address_t *addr_nbr1,
             const ip46_address_t *addr_nbr2)
{
    fib_node_index_t mfei, mfei_dflt, mfei_no_f, mfei_s_g, mfei_g_1, mfei_g_2, mfei_g_3, mfei_g_m;
    u32 fib_index, n_entries, n_itfs, n_reps, n_pls;
    fib_node_index_t ai_1, ai_2, ai_3, ai_nbr1, ai_nbr2;
    test_main_t *tm;
    int res;

    mfib_prefix_t all_1s;
    clib_memset(&all_1s, 0xfd, sizeof(all_1s));

    res = 0;
    n_entries = pool_elts(mfib_entry_pool);
    n_itfs = pool_elts(mfib_itf_pool);
    n_reps = pool_elts(replicate_pool);
    n_pls = fib_path_list_pool_size();
    tm = &test_main;

    ai_1 = adj_mcast_add_or_lock(PROTO,
                                 LINKT,
                                 tm->hw[1]->sw_if_index);
    ai_2 = adj_mcast_add_or_lock(PROTO,
                                 LINKT,
                                 tm->hw[2]->sw_if_index);
    ai_3 = adj_mcast_add_or_lock(PROTO,
                                 LINKT,
                                 tm->hw[3]->sw_if_index);
    ai_nbr1 = adj_nbr_add_or_lock(PROTO,
                                  LINKT,
                                  addr_nbr1,
                                  tm->hw[0]->sw_if_index);
    ai_nbr2 = adj_nbr_add_or_lock(PROTO,
                                  LINKT,
                                  addr_nbr2,
                                  tm->hw[0]->sw_if_index);

    MFIB_TEST(3 == adj_mcast_db_size(), "3 MCAST adjs");

    /* Find or create FIB table 11 */
    fib_index = mfib_table_find_or_create_and_lock(PROTO, 11, MFIB_SOURCE_API);

    fib_table_entry_update_one_path(0,
                                    pfx_itf,
				    FIB_SOURCE_INTERFACE,
				    (FIB_ENTRY_FLAG_CONNECTED |
				     FIB_ENTRY_FLAG_ATTACHED),
				    DPO_PROTO_IP4,
				    NULL,
				    tm->hw[0]->sw_if_index,
				    ~0, // invalid fib index
				    1, // weight
				    NULL,
				    FIB_ROUTE_PATH_FLAG_NONE);

    mfib_prefix_t pfx_dft = {
        .fp_len = 0,
        .fp_proto = PROTO,
    };
    mfei_dflt = mfib_table_lookup_exact_match(fib_index, &pfx_dft);
    MFIB_TEST(FIB_NODE_INDEX_INVALID != mfei_dflt, "(*,*) presnet");
    MFIB_TEST(!mfib_test_entry(mfei_dflt,
                               MFIB_ENTRY_FLAG_DROP,
                               0),
              "(*,*) no replcaitions");

    MFIB_TEST(FIB_NODE_INDEX_INVALID != mfei_dflt, "(*,*) presnet");
    MFIB_TEST(!mfib_test_entry(mfei_dflt,
                               MFIB_ENTRY_FLAG_DROP,
                               0),
              "(*,*) no replcaitions");


    fib_route_path_t path_via_if0 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };

    mfib_table_entry_path_update(fib_index,
                                 pfx_no_forward,
                                 MFIB_SOURCE_API,
                                 &path_via_if0,
                                 MFIB_ITF_FLAG_ACCEPT);

    mfei_no_f = mfib_table_lookup_exact_match(fib_index, pfx_no_forward);
    MFIB_TEST(!mfib_test_entry(mfei_no_f,
                               MFIB_ENTRY_FLAG_NONE,
                               0),
              "%U no replcaitions",
              format_mfib_prefix, pfx_no_forward);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_no_f, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));

    fib_route_path_t path_via_if1 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[1]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_via_if2 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[2]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_via_if3 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[3]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_for_us = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = zero_addr,
        .frp_sw_if_index = 0xffffffff,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = FIB_ROUTE_PATH_LOCAL,
    };

    /*
     * An (S,G) with 1 accepting and 3 forwarding paths
     */
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if0,
                                 MFIB_ITF_FLAG_ACCEPT);
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if1,
                                 MFIB_ITF_FLAG_FORWARD);
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if2,
                                 MFIB_ITF_FLAG_FORWARD);
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 (MFIB_ITF_FLAG_FORWARD |
                                  MFIB_ITF_FLAG_NEGATE_SIGNAL));

    mfei_s_g = mfib_table_lookup_exact_match(fib_index, pfx_s_g);

    MFIB_TEST(FIB_NODE_INDEX_INVALID != mfei_s_g,
              "%U present",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST(!mfib_test_entry(mfei_s_g,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate ok",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_s_g, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_s_g, tm->hw[1]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_s_g, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_s_g, tm->hw[3]->sw_if_index,
                                      (MFIB_ITF_FLAG_FORWARD |
                                       MFIB_ITF_FLAG_NEGATE_SIGNAL)));

    /*
     * A (*,G), which the same G as the (S,G).
     * different paths. test our LPM.
     */
    mfei_g_1 = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_1,
                                            MFIB_SOURCE_API,
                                            &path_via_if0,
                                            MFIB_ITF_FLAG_ACCEPT);
    mfib_table_entry_path_update(fib_index,
                                 pfx_star_g_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if1,
                                 MFIB_ITF_FLAG_FORWARD);

    /*
     * test we find the *,G and S,G via LPM and exact matches
     */
    mfei = mfib_table_lookup_exact_match(fib_index,
                                         pfx_star_g_1);
    MFIB_TEST(mfei == mfei_g_1,
              "%U found via exact match",
              format_mfib_prefix, pfx_star_g_1);
    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_MCAST, ai_1),
              "%U replicate ok",
              format_mfib_prefix, pfx_star_g_1);

    mfei = mfib_table_lookup(fib_index,
                             pfx_star_g_1);
    MFIB_TEST(mfei == mfei_g_1,
              "%U found via LP match",
              format_mfib_prefix, pfx_star_g_1);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_MCAST, ai_1),
              "%U replicate ok",
              format_mfib_prefix, pfx_star_g_1);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_s_g);
    MFIB_TEST(mfei == mfei_s_g,
              "%U found via exact match",
              format_mfib_prefix, pfx_s_g);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    mfei = mfib_table_lookup(fib_index, pfx_s_g);
    MFIB_TEST(mfei == mfei_s_g,
              "%U found via LP match",
              format_mfib_prefix, pfx_s_g);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);

    /*
     * A (*,G/m), which the same root G as the (*,G).
     * different paths. test our LPM.
     */
    mfei_g_m = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_slash_m,
                                            MFIB_SOURCE_API,
                                            &path_via_if2,
                                            MFIB_ITF_FLAG_ACCEPT);
    mfib_table_entry_path_update(fib_index,
                                 pfx_star_g_slash_m,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 MFIB_ITF_FLAG_FORWARD);

    /*
     * test we find the (*,G/m), (*,G) and (S,G) via LPM and exact matches
     */
    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_1);
    MFIB_TEST((mfei_g_1 == mfei),
              "%U found via DP LPM: %d",
              format_mfib_prefix, pfx_star_g_1, mfei);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_MCAST, ai_1),
              "%U replicate ok",
              format_mfib_prefix, pfx_star_g_1);

    mfei = mfib_table_lookup(fib_index, pfx_star_g_1);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_MCAST, ai_1),
              "%U replicate ok",
              format_mfib_prefix, pfx_star_g_1);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_s_g);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    mfei = mfib_table_lookup(fib_index, pfx_s_g);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_slash_m);
    MFIB_TEST(mfei = mfei_g_m,
              "%U Found via exact match",
              format_mfib_prefix, pfx_star_g_slash_m);
    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_star_g_slash_m);
    MFIB_TEST(mfei_g_m == mfib_table_lookup(fib_index, pfx_star_g_slash_m),
              "%U found via LPM",
              format_mfib_prefix, pfx_star_g_slash_m);

    /*
     * Add a for-us path
     */
    mfei = mfib_table_entry_path_update(fib_index,
                                        pfx_s_g,
                                        MFIB_SOURCE_API,
                                        &path_for_us,
                                        MFIB_ITF_FLAG_FORWARD);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               4,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3,
                               DPO_RECEIVE, 0),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);

    /*
     * remove a for-us path
     */
    mfib_table_entry_path_remove(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_for_us);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);

    /*
     * update an existing forwarding path to be only accepting
     *   - expect it to be removed from the replication set.
     */
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 MFIB_ITF_FLAG_ACCEPT);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               2,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[3]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    /*
     * Make the path forwarding again
     *  - expect it to be added back to the replication set
     */
    mfib_table_entry_path_update(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 (MFIB_ITF_FLAG_FORWARD |
                                  MFIB_ITF_FLAG_ACCEPT |
                                  MFIB_ITF_FLAG_NEGATE_SIGNAL));

    mfei = mfib_table_lookup_exact_match(fib_index,
                                         pfx_s_g);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[3]->sw_if_index,
                                      (MFIB_ITF_FLAG_FORWARD |
                                       MFIB_ITF_FLAG_ACCEPT |
                                       MFIB_ITF_FLAG_NEGATE_SIGNAL)));

    /*
     * update flags on the entry
     */
    mfib_table_entry_update(fib_index,
                            pfx_s_g,
                            MFIB_SOURCE_API,
                            MFIB_RPF_ID_NONE,
                            MFIB_ENTRY_FLAG_SIGNAL);
    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_SIGNAL,
                               3,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2,
                               DPO_ADJACENCY_MCAST, ai_3),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);

    /*
     * remove paths
     */
    mfib_table_entry_path_remove(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if3);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_SIGNAL,
                               2,
                               DPO_ADJACENCY_MCAST, ai_1,
                               DPO_ADJACENCY_MCAST, ai_2),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    mfib_table_entry_path_remove(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if1);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_SIGNAL,
                               1,
                               DPO_ADJACENCY_MCAST, ai_2),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    /*
     * remove the accpeting only interface
     */
    mfib_table_entry_path_remove(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if0);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_SIGNAL,
                               1,
                               DPO_ADJACENCY_MCAST, ai_2),
              "%U replicate OK",
              format_mfib_prefix, pfx_s_g);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(!mfib_test_entry_no_itf(mfei, tm->hw[0]->sw_if_index));
    MFIB_TEST_NS(!mfib_test_entry_no_itf(mfei, tm->hw[1]->sw_if_index));
    MFIB_TEST_NS(!mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    /*
     * remove the last path, the entry still has flags so it remains
     */
    mfib_table_entry_path_remove(fib_index,
                                 pfx_s_g,
                                 MFIB_SOURCE_API,
                                 &path_via_if2);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_SIGNAL,
                               0),
              "%U no replications",
              format_mfib_prefix, pfx_s_g);

    /*
     * update flags on the entry
     */
    mfib_table_entry_update(fib_index,
                            pfx_s_g,
                            MFIB_SOURCE_API,
                            MFIB_RPF_ID_NONE,
                            (MFIB_ENTRY_FLAG_SIGNAL |
                             MFIB_ENTRY_FLAG_CONNECTED));
    MFIB_TEST(!mfib_test_entry(mfei,
                               (MFIB_ENTRY_FLAG_SIGNAL |
                                MFIB_ENTRY_FLAG_CONNECTED),
                               0),
              "%U no replications",
              format_mfib_prefix, pfx_s_g);

    /*
     * An entry with a NS interface
     */
    mfei_g_2 = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_2,
                                            MFIB_SOURCE_API,
                                            &path_via_if0,
                                            (MFIB_ITF_FLAG_ACCEPT |
                                             MFIB_ITF_FLAG_NEGATE_SIGNAL));
    MFIB_TEST(!mfib_test_entry(mfei_g_2,
                               MFIB_ENTRY_FLAG_NONE,
                               0),
              "%U No replications",
              format_mfib_prefix, pfx_star_g_2);

    /*
     * Simulate a signal from the data-plane
     */
    {
        mfib_entry_t *mfe;
        mfib_itf_t *mfi;

        mfe = mfib_entry_get(mfei_g_2);
        mfi = mfib_entry_get_itf(mfe, path_via_if0.frp_sw_if_index);

        mfib_signal_push(mfe, mfi, NULL);
    }

    /*
     * An entry with a NS interface
     */
    mfei_g_3 = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_3,
                                            MFIB_SOURCE_API,
                                            &path_via_if0,
                                            (MFIB_ITF_FLAG_ACCEPT |
                                             MFIB_ITF_NEGATE_SIGNAL));
    MFIB_TEST(!mfib_test_entry(mfei_g_3,
                               MFIB_ENTRY_FLAG_NONE,
                               0),
              "%U No replications",
              format_mfib_prefix, pfx_star_g_3);

    /*
     * Simulate a signal from the data-plane
     */
    {
        mfib_entry_t *mfe;
        mfib_itf_t *mfi;

        mfe = mfib_entry_get(mfei_g_3);
        mfi = mfib_entry_get_itf(mfe, path_via_if0.frp_sw_if_index);

        mfib_signal_push(mfe, mfi, NULL);
    }

    if (FIB_PROTOCOL_IP6 == PROTO)
    {
        /*
         * All the entries are present. let's ensure we can find them all
         * via exact and longest prefix matches.
         */
        /*
         * A source address we will never match
         */
        ip6_address_t src = {
            .as_u64[0] = clib_host_to_net_u64(0x3001000000000000),
            .as_u64[1] = clib_host_to_net_u64(0xffffffffffffffff),
        };

        /*
         * Find the (*,G/m)
         */
        MFIB_TEST((mfei_g_m == ip6_mfib_table_lookup2(
                       ip6_mfib_get(fib_index),
                       &src,
                       &pfx_star_g_slash_m->fp_grp_addr.ip6)),
                  "%U found via DP LPM grp=%U",
                  format_mfib_prefix, pfx_star_g_slash_m,
                  format_ip6_address, &pfx_star_g_slash_m->fp_grp_addr.ip6);

        ip6_address_t tmp = pfx_star_g_slash_m->fp_grp_addr.ip6;
        tmp.as_u8[15] = 0xff;

        MFIB_TEST((mfei_g_m == ip6_mfib_table_lookup2(
                       ip6_mfib_get(fib_index),
                       &pfx_s_g->fp_src_addr.ip6,
                       &tmp)),
                  "%U found via DP LPM grp=%U",
                  format_mfib_prefix, pfx_star_g_slash_m,
                  format_ip6_address, &tmp);

        /*
         * Find the (S,G).
         */
        mfei = ip6_mfib_table_lookup2(ip6_mfib_get(fib_index),
                                      &pfx_s_g->fp_src_addr.ip6,
                                      &pfx_s_g->fp_grp_addr.ip6);
        MFIB_TEST((mfei_s_g == mfei),
                  "%U found via DP LPM: %d",
                  format_mfib_prefix, pfx_s_g, mfei);

        /*
         * Find the 3 (*,G) s
         */
        mfei = ip6_mfib_table_lookup2(ip6_mfib_get(fib_index),
                                      &src,
                                      &pfx_star_g_1->fp_grp_addr.ip6);
        MFIB_TEST((mfei_g_1 == mfei),
                  "%U found via DP LPM: %d",
                  format_mfib_prefix, pfx_star_g_1, mfei);
        mfei = ip6_mfib_table_lookup2(ip6_mfib_get(fib_index),
                                      &src,
                                      &pfx_star_g_2->fp_grp_addr.ip6);
        MFIB_TEST((mfei_g_2 == mfei),
                  "%U found via DP LPM: %d",
                  format_mfib_prefix, pfx_star_g_2, mfei);
        mfei = ip6_mfib_table_lookup2(ip6_mfib_get(fib_index),
                                      &src,
                                      &pfx_star_g_3->fp_grp_addr.ip6);
        MFIB_TEST((mfei_g_3 == mfei),
                  "%U found via DP LPM: %d",
                  format_mfib_prefix, pfx_star_g_3, mfei);
    }

    /*
     * remove flags on the entry. This is the last of the
     * state associated with the entry, so now it goes.
     */
    mfib_table_entry_update(fib_index,
                            pfx_s_g,
                            MFIB_SOURCE_API,
                            MFIB_RPF_ID_NONE,
                            MFIB_ENTRY_FLAG_NONE);
    mfei = mfib_table_lookup_exact_match(fib_index,
                                         pfx_s_g);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U gone",
              format_mfib_prefix, pfx_s_g);

    /*
     * remove the last path on the no forward entry - the last entry
     */
    mfib_table_entry_path_remove(fib_index,
                                 pfx_no_forward,
                                 MFIB_SOURCE_API,
                                 &path_via_if0);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_no_forward);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U gone",
              format_mfib_prefix, pfx_no_forward);

    /*
     * hard delete the (*,232.1.1.1)
     */
    mfib_table_entry_delete(fib_index,
                            pfx_star_g_1,
                            MFIB_SOURCE_API);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_1);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U gone",
              format_mfib_prefix, pfx_star_g_1);
    /*
     * remove the entry whilst the signal is pending
     */
    mfib_table_entry_delete(fib_index,
                            pfx_star_g_2,
                            MFIB_SOURCE_API);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_2);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U Gone",
              format_mfib_prefix, pfx_star_g_2);
    mfib_table_entry_delete(fib_index,
                            pfx_star_g_3,
                            MFIB_SOURCE_API);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_3);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U Gone",
              format_mfib_prefix, pfx_star_g_3);

    mfib_table_entry_delete(fib_index,
                            pfx_star_g_slash_m,
                            MFIB_SOURCE_API);

    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_slash_m);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U Gone",
              format_mfib_prefix, pfx_star_g_slash_m);

    /*
     * Entries with paths via unicast next-hops
     */
    fib_route_path_t path_via_nbr1 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = *addr_nbr1,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_via_nbr2 = {
        .frp_proto = fib_proto_to_dpo(PROTO),
        .frp_addr = *addr_nbr2,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };

    mfei_g_1 = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_1,
                                            MFIB_SOURCE_API,
                                            &path_via_nbr1,
                                            (MFIB_ITF_FLAG_FORWARD));
    mfei_g_1 = mfib_table_entry_path_update(fib_index,
                                            pfx_star_g_1,
                                            MFIB_SOURCE_API,
                                            &path_via_nbr2,
                                            (MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST(!mfib_test_entry(mfei_g_1,
                               MFIB_ENTRY_FLAG_NONE,
                               2,
                               DPO_ADJACENCY_INCOMPLETE, ai_nbr1,
                               DPO_ADJACENCY_INCOMPLETE, ai_nbr2),
              "%U replicate OK",
              format_mfib_prefix, pfx_star_g_1);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_g_1, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));

    mfib_table_entry_path_remove(fib_index,
                                 pfx_star_g_1,
                                 MFIB_SOURCE_API,
                                 &path_via_nbr1);

    MFIB_TEST(!mfib_test_entry(mfei_g_1,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_ADJACENCY_INCOMPLETE, ai_nbr2),
              "%U replicate OK",
              format_mfib_prefix, pfx_star_g_1);
    MFIB_TEST_NS(!mfib_test_entry_itf(mfei_g_1, tm->hw[0]->sw_if_index,
                                      MFIB_ITF_FLAG_FORWARD));

    mfib_table_entry_path_remove(fib_index,
                                 pfx_star_g_1,
                                 MFIB_SOURCE_API,
                                 &path_via_nbr2);
    mfei = mfib_table_lookup_exact_match(fib_index, pfx_star_g_1);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei,
              "%U Gone",
              format_mfib_prefix, pfx_star_g_1);

    /*
     * Add a prefix as a special/exclusive route
     */
    dpo_id_t td = DPO_INVALID;
    index_t repi = replicate_create(1, fib_proto_to_dpo(PROTO));

    dpo_set(&td, DPO_ADJACENCY_MCAST, fib_proto_to_dpo(PROTO), ai_2);
    replicate_set_bucket(repi, 0, &td);

    mfei = mfib_table_entry_special_add(fib_index,
                                        pfx_star_g_3,
                                        MFIB_SOURCE_SRv6,
                                        MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF,
                                        repi);
    MFIB_TEST(!mfib_test_entry(mfei,
                               (MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF |
                                MFIB_ENTRY_FLAG_EXCLUSIVE),
                               1,
                               DPO_ADJACENCY_MCAST, ai_2),
              "%U exclusive replicate OK",
              format_mfib_prefix, pfx_star_g_3);

    /*
     * update a special/exclusive route
     */
    index_t repi2 = replicate_create(1, fib_proto_to_dpo(PROTO));

    dpo_set(&td, DPO_ADJACENCY_MCAST, fib_proto_to_dpo(PROTO), ai_1);
    replicate_set_bucket(repi2, 0, &td);

    mfei = mfib_table_entry_special_add(fib_index,
                                        pfx_star_g_3,
                                        MFIB_SOURCE_SRv6,
                                        MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF,
                                        repi2);
    MFIB_TEST(!mfib_test_entry(mfei,
                               (MFIB_ENTRY_FLAG_ACCEPT_ALL_ITF |
                                MFIB_ENTRY_FLAG_EXCLUSIVE),
                               1,
                               DPO_ADJACENCY_MCAST, ai_1),
              "%U exclusive update replicate OK",
              format_mfib_prefix, pfx_star_g_3);

    mfib_table_entry_delete(fib_index,
                            pfx_star_g_3,
                            MFIB_SOURCE_SRv6);
    dpo_reset(&td);

    /*
     * A Multicast LSP. This a mLDP head-end
     */
    fib_node_index_t ai_mpls_10_10_10_1, lfei;
    ip46_address_t nh_10_10_10_1 = {
	.ip4 = {
	    .as_u32 = clib_host_to_net_u32(0x0a0a0a01),
	},
    };
    ai_mpls_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_10_1,
                                             tm->hw[0]->sw_if_index);

    fib_prefix_t pfx_3500 = {
	.fp_len = 21,
	.fp_proto = FIB_PROTOCOL_MPLS,
	.fp_label = 3500,
	.fp_eos = MPLS_EOS,
	.fp_payload_proto = DPO_PROTO_IP4,
    };
    fib_test_rep_bucket_t mc_0 = {
        .type = FT_REP_LABEL_O_ADJ,
	.label_o_adj = {
	    .adj = ai_mpls_10_10_10_1,
	    .label = 3300,
	    .eos = MPLS_EOS,
	},
    };
    fib_mpls_label_t *l3300 = NULL, fml3300 = {
        .fml_value = 3300,
    };
    vec_add1(l3300, fml3300);

    /*
     * MPLS enable an interface so we get the MPLS table created
     */
    mpls_table_create(MPLS_FIB_DEFAULT_TABLE_ID, FIB_SOURCE_API, NULL);
    mpls_sw_interface_enable_disable(&mpls_main,
                                     tm->hw[0]->sw_if_index,
                                     1, 0);

    lfei = fib_table_entry_update_one_path(0, // default MPLS Table
                                           &pfx_3500,
                                           FIB_SOURCE_API,
                                           FIB_ENTRY_FLAG_MULTICAST,
                                           DPO_PROTO_IP4,
                                           &nh_10_10_10_1,
                                           tm->hw[0]->sw_if_index,
                                           ~0, // invalid fib index
                                           1,
                                           l3300,
                                           FIB_ROUTE_PATH_FLAG_NONE);
    MFIB_TEST(!fib_test_validate_entry(lfei,
                                       FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                       1,
                                       &mc_0),
              "3500 via replicate over 10.10.10.1");

    /*
     * An (S,G) that resolves via the mLDP head-end
     */
    fib_route_path_t path_via_mldp = {
        .frp_proto = DPO_PROTO_MPLS,
        .frp_local_label = pfx_3500.fp_label,
        .frp_eos = MPLS_EOS,
        .frp_sw_if_index = 0xffffffff,
        .frp_fib_index = 0,
        .frp_weight = 1,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
    };
    dpo_id_t mldp_dpo = DPO_INVALID;

    fib_entry_contribute_forwarding(lfei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                    &mldp_dpo);

    mfei = mfib_table_entry_path_update(fib_index,
                                        pfx_s_g,
                                        MFIB_SOURCE_API,
                                        &path_via_mldp,
                                        MFIB_ITF_FLAG_FORWARD);

    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               1,
                               DPO_REPLICATE, mldp_dpo.dpoi_index),
              "%U over-mLDP replicate OK",
              format_mfib_prefix, pfx_s_g);

    /*
     * add a for-us path. this tests two types of non-attached paths on one entry
     */
    mfei = mfib_table_entry_path_update(fib_index,
                                        pfx_s_g,
                                        MFIB_SOURCE_API,
                                        &path_for_us,
                                        MFIB_ITF_FLAG_FORWARD);
    MFIB_TEST(!mfib_test_entry(mfei,
                               MFIB_ENTRY_FLAG_NONE,
                               2,
                               DPO_REPLICATE, mldp_dpo.dpoi_index,
                               DPO_RECEIVE, 0),
              "%U mLDP+for-us replicate OK",
              format_mfib_prefix, pfx_s_g);

    mfib_table_entry_delete(fib_index,
                            pfx_s_g,
                            MFIB_SOURCE_API);
    fib_table_entry_delete(0,
                           &pfx_3500,
                           FIB_SOURCE_API);
    dpo_reset(&mldp_dpo);

    /*
     * Unlock the table - it's the last lock so should be gone thereafter
     */
    mfib_table_unlock(fib_index, PROTO, MFIB_SOURCE_API);

    MFIB_TEST((FIB_NODE_INDEX_INVALID ==
               mfib_table_find(PROTO, fib_index)),
              "MFIB table %d gone", fib_index);

    adj_unlock(ai_1);
    adj_unlock(ai_2);
    adj_unlock(ai_3);
    adj_unlock(ai_nbr1);
    adj_unlock(ai_nbr2);

    /*
     * MPLS disable the interface
     */
    mpls_sw_interface_enable_disable(&mpls_main,
                                     tm->hw[0]->sw_if_index,
                                     0, 0);
    mpls_table_delete(MPLS_FIB_DEFAULT_TABLE_ID, FIB_SOURCE_API);

    /*
     * remove the connected
     */
    fib_table_entry_delete(0, pfx_itf, FIB_SOURCE_INTERFACE);

    /*
     * test we've leaked no resources
     */
    MFIB_TEST(0 == adj_mcast_db_size(), "%d MCAST adjs", adj_mcast_db_size());
    MFIB_TEST(n_pls == fib_path_list_pool_size(), "%d=%d path-lists",
              n_pls, fib_path_list_pool_size());
    MFIB_TEST(n_reps == pool_elts(replicate_pool), "%d=%d replicates",
              n_reps, pool_elts(replicate_pool));
    MFIB_TEST(n_entries == pool_elts(mfib_entry_pool),
              " No more entries %d!=%d",
              n_entries, pool_elts(mfib_entry_pool));
    MFIB_TEST(n_itfs == pool_elts(mfib_itf_pool),
              " No more Interfaces %d!=%d",
              n_itfs, pool_elts(mfib_itf_pool));

    return (res);
}

static int
mfib_test_v4 (void)
{
    const mfib_prefix_t pfx_224_s_8 = {
        .fp_len = 8,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xe0000000),
        }
    };
    const mfib_prefix_t pfx_1_1_1_1_c_239_1_1_1 = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010101),
        },
        .fp_src_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010101),
        },
    };
    const mfib_prefix_t pfx_239_1_1_1 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010101),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };
    const mfib_prefix_t pfx_239_1_1_2 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010102),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };
    const mfib_prefix_t pfx_239_1_1_3 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010103),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };
    const mfib_prefix_t pfx_239 = {
        .fp_len = 8,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef000000),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };
    const fib_prefix_t pfx_itf = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
        },
    };
    const ip46_address_t nbr1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a0b),
    };
    const ip46_address_t nbr2 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a0c),
    };
    return (mfib_test_i(FIB_PROTOCOL_IP4,
                        VNET_LINK_IP4,
                        &pfx_224_s_8,
                        &pfx_1_1_1_1_c_239_1_1_1,
                        &pfx_239_1_1_1,
                        &pfx_239_1_1_2,
                        &pfx_239_1_1_3,
                        &pfx_239,
                        &pfx_itf,
                        &nbr1,
                        &nbr2));
}

static int
mfib_test_v6 (void)
{
    const mfib_prefix_t pfx_ffd_s_12 = {
        .fp_len = 12,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xffd0000000000000),
        }
    };
    const mfib_prefix_t pfx_2001_1_c_ff_1 = {
        .fp_len = 256,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xff01000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000001),
        },
        .fp_src_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0x2001000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000001),
        },
    };
    const mfib_prefix_t pfx_ff_1 = {
        .fp_len = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xff01000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000001),
        },
    };
    const mfib_prefix_t pfx_ff_2 = {
        .fp_len = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xff01000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000002),
        },
    };
    const mfib_prefix_t pfx_ff_3 = {
        /*
         * this is the ALL DHCP routers address
         */
        .fp_len = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xff02000100000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000002),
        },
    };
    const mfib_prefix_t pfx_ff = {
        .fp_len = 16,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_grp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0xff01000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000000),
        },
    };
    const fib_prefix_t pfx_itf = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0x2001000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000001),
        },
    };
    const ip46_address_t nbr1 = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0x2001000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000002),
    };
    const ip46_address_t nbr2 = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0x2001000000000000),
            .ip6.as_u64[1] = clib_host_to_net_u64(0x0000000000000003),
    };

    return (mfib_test_i(FIB_PROTOCOL_IP6,
                        VNET_LINK_IP6,
                        &pfx_ffd_s_12,
                        &pfx_2001_1_c_ff_1,
                        &pfx_ff_1,
                        &pfx_ff_2,
                        &pfx_ff_3,
                        &pfx_ff,
                        &pfx_itf,
                        &nbr1,
                        &nbr2));
}

static clib_error_t *
mfib_test (vlib_main_t * vm,
           unformat_input_t * input,
           vlib_cli_command_t * cmd_arg)
{
    int res = 0;

    res += mfib_test_mk_intf(4);
    res += mfib_test_v4();

    if (res)
    {
        return clib_error_return(0, "MFIB Unit Test Failed");
    }

    res += mfib_test_v6();

    if (res)
    {
        return clib_error_return(0, "MFIB Unit Test Failed");
    }
    else
    {
        return (NULL);
    }
}

VLIB_CLI_COMMAND (test_fib_command, static) = {
    .path = "test mfib",
    .short_help = "mfib unit tests - DO NOT RUN ON A LIVE SYSTEM",
    .function = mfib_test,
};

clib_error_t *
mfib_test_init (vlib_main_t *vm)
{
    return 0;
}

VLIB_INIT_FUNCTION (mfib_test_init);
