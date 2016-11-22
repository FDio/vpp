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

#include <vnet/dpo/replicate_dpo.h>
#include <vnet/adj/adj_mcast.h>

#define MFIB_TEST_I(_cond, _comment, _args...)			\
({								\
    int _evald = (_cond);					\
    if (!(_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
    } else {							\
        fformat(stderr, "PASS:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
    }								\
    _evald;							\
})
#define MFIB_TEST(_cond, _comment, _args...)			\
{								\
    if (!MFIB_TEST_I(_cond, _comment, ##_args)) {		\
        return;\
        ASSERT(!("FAIL: " _comment));				\
    }								\
}
#define MFIB_TEST_NS(_cond)                                     \
{								\
    if (!MFIB_TEST_I(_cond, "")) {                              \
        return;\
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

static void
mfib_test_mk_intf (u32 ninterfaces)
{
    clib_error_t * error = NULL;
    test_main_t *tm = &test_main;
    u8 byte;
    u32 i;

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
}

#define MFIB_TEST_REP(_cond, _comment, _args...)		\
{								\
    if (!MFIB_TEST_I(_cond, _comment, ##_args)) {		\
        return (0);						\
    }								\
}

static int
mfib_test_validate_rep_v (const replicate_t *rep,
                          u16 n_buckets,
                          va_list ap)
{
    const dpo_id_t *dpo;
    adj_index_t ai;
    dpo_type_t dt;
    int bucket;

    MFIB_TEST_REP((n_buckets == rep->rep_n_buckets),
                  "n_buckets = %d", rep->rep_n_buckets);

    for (bucket = 0; bucket < n_buckets; bucket++)
    {
        dt = va_arg(ap, int);  // type promotion
        ai = va_arg(ap, adj_index_t);
        dpo = replicate_get_bucket_i(rep, bucket);

        MFIB_TEST_REP((dt == dpo->dpoi_type),
                      "bucket %d stacks on %U",
                      bucket,
                      format_dpo_type, dpo->dpoi_type);

        if (DPO_RECEIVE != dt)
        {
            MFIB_TEST_REP((ai == dpo->dpoi_index),
                          "bucket %d stacks on %U",
                          bucket,
                          format_dpo_id, dpo, 0);
        }
    }
    return (!0);
}

static int
mfib_test_entry (fib_node_index_t fei,
                 mfib_entry_flags_t eflags,
                 u16 n_buckets,
                 ...)
{
    const mfib_entry_t *mfe;
    const replicate_t *rep;
    mfib_prefix_t pfx;
    va_list ap;

    va_start(ap, n_buckets);

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
        return (!0);
    }
    else
    {
        rep = replicate_get(mfe->mfe_rep.dpoi_index);

        MFIB_TEST_REP((DPO_REPLICATE == mfe->mfe_rep.dpoi_type),
                      "%U links to %U",
                      format_mfib_prefix, &pfx,
                      format_dpo_type, mfe->mfe_rep.dpoi_type);

        return (mfib_test_validate_rep_v(rep, n_buckets, ap));
    }
}

static int
mfib_test_entry_itf (fib_node_index_t fei,
                     u32 sw_if_index,
                     mfib_itf_flags_t flags)
{
    const mfib_entry_t *mfe;
    const mfib_itf_t *mfi;
    mfib_prefix_t pfx;

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

    return (!0);
}

static int
mfib_test_entry_no_itf (fib_node_index_t fei,
                        u32 sw_if_index)
{
    const mfib_entry_t *mfe;
    const mfib_itf_t *mfi;
    mfib_prefix_t pfx;

    mfe = mfib_entry_get(fei);
    mfi = mfib_entry_get_itf(mfe, sw_if_index);
    mfib_entry_get_prefix(fei, &pfx);

    MFIB_TEST_REP((NULL == mfi),
                  "%U has no interface %d",
                  format_mfib_prefix, &pfx, sw_if_index);

    return (!0);
}

static void
mfib_test_v4 (void)
{
    fib_node_index_t mfei, ai_1, ai_2, ai_3;
    u32 fib_index, n_entries;
    test_main_t *tm;

    n_entries = pool_elts(mfib_entry_pool);
    tm = &test_main;

    ai_1 = adj_mcast_add_or_lock(FIB_PROTOCOL_IP4,
                                 VNET_LINK_IP4,
                                 tm->hw[1]->sw_if_index);
    ai_2 = adj_mcast_add_or_lock(FIB_PROTOCOL_IP4,
                                 VNET_LINK_IP4,
                                 tm->hw[2]->sw_if_index);
    ai_3 = adj_mcast_add_or_lock(FIB_PROTOCOL_IP4,
                                 VNET_LINK_IP4,
                                 tm->hw[3]->sw_if_index);

    MFIB_TEST(3 == adj_mcast_db_size(), "3 MCAST adjs");

    /* Find or create FIB table 11 */
    fib_index = mfib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4, 11);

    mfib_prefix_t pfx_dft = {
        .fp_len = 0,
        .fp_proto = FIB_PROTOCOL_IP4,
    };
    mfei = mfib_table_lookup_exact_match(fib_index, &pfx_dft);
    MFIB_TEST(FIB_NODE_INDEX_INVALID != mfei, "(*,*) presnet");
    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_DROP,
                              0),
              "(*,*) no replcaitions");

    mfib_prefix_t pfx_224_s_8 = {
        .fp_len = 8,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xe0000000),
        }
    };

    fib_route_path_t path_via_if0 = {
        .frp_proto = FIB_PROTOCOL_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };

    mfib_table_entry_path_update(fib_index,
                                 &pfx_224_s_8,
                                 MFIB_SOURCE_API,
                                 &path_via_if0,
                                 MFIB_ITF_FLAG_INTERNAL_COPY);

    mfei = mfib_table_lookup_exact_match(fib_index, &pfx_224_s_8);
    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              0),
              "(*,224.0.0.0/8) no replcaitions");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_INTERNAL_COPY));
    fib_route_path_t path_via_if1 = {
        .frp_proto = FIB_PROTOCOL_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[1]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_via_if2 = {
        .frp_proto = FIB_PROTOCOL_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[2]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_via_if3 = {
        .frp_proto = FIB_PROTOCOL_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = tm->hw[3]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = 0,
    };
    fib_route_path_t path_for_us = {
        .frp_proto = FIB_PROTOCOL_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = 0xffffffff,
        .frp_fib_index = ~0,
        .frp_weight = 0,
        .frp_flags = FIB_ROUTE_PATH_LOCAL,
    };

    /*
     * An (S,G) with 1 accepting and 3 forwarding paths
     */
    mfib_prefix_t pfx_1_1_1_1_c_239_1_1_1 = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010101),
        },
        .fp_src_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010101),
        },
    };
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if0,
                                 MFIB_ITF_FLAG_ACCEPT);
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if1,
                                 MFIB_ITF_FLAG_FORWARD);
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if2,
                                 MFIB_ITF_FLAG_FORWARD);
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 (MFIB_ITF_FLAG_FORWARD |
                                  MFIB_ITF_FLAG_NEGATE_SIGNAL));

    mfei = mfib_table_lookup_exact_match(fib_index,
                                         &pfx_1_1_1_1_c_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
     MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[3]->sw_if_index,
                                     (MFIB_ITF_FLAG_FORWARD |
                                      MFIB_ITF_FLAG_NEGATE_SIGNAL)));

    /*
     * A (*,G), which the same G as the (S,G).
     * different paths. test our LPM.
     */
    mfib_prefix_t pfx_239_1_1_1 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_grp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xef010101),
        },
        .fp_src_addr = {
            .ip4.as_u32 = 0,
        },
    };
    mfib_table_entry_path_update(fib_index,
                                 &pfx_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if0,
                                 MFIB_ITF_FLAG_ACCEPT);
    mfib_table_entry_path_update(fib_index,
                                 &pfx_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if1,
                                 MFIB_ITF_FLAG_FORWARD);

    /*
     * test we find the *,G and S,G via LPM and exact matches
     */
    mfei = mfib_table_lookup_exact_match(fib_index,
                                         &pfx_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              1,
                              DPO_ADJACENCY_MCAST, ai_1),
              "(*,239.1.1.1) replcaite ok");

    mfei = mfib_table_lookup(fib_index,
                             &pfx_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              1,
                              DPO_ADJACENCY_MCAST, ai_1),
              "(*,239.1.1.1) replcaite ok");

    mfei = mfib_table_lookup_exact_match(fib_index,
                                         &pfx_1_1_1_1_c_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    mfei = mfib_table_lookup(fib_index,
                             &pfx_1_1_1_1_c_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");

    /*
     * Add a for-us path
     */
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_for_us,
                                 MFIB_ITF_FLAG_FORWARD);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              4,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3,
                              DPO_RECEIVE, 0),
              "(1.1.1.1,239.1.1.1) replcaite ok");

    /*
     * remove a for-us path
     */
    mfib_table_entry_path_remove(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_for_us);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");

    /*
     * update an existing forwarding path to be only accepting
     *   - expect it to be removed from the replication set.
     */
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 MFIB_ITF_FLAG_ACCEPT);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              2,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
     MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[3]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
    /*
     * Make the path forwarding again
     *  - expect it to be added back to the replication set
     */
    mfib_table_entry_path_update(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if3,
                                 (MFIB_ITF_FLAG_FORWARD |
                                  MFIB_ITF_FLAG_ACCEPT |
                                  MFIB_ITF_FLAG_NEGATE_SIGNAL));

    mfei = mfib_table_lookup_exact_match(fib_index,
                                         &pfx_1_1_1_1_c_239_1_1_1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_NONE,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
     MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[3]->sw_if_index,
                                     (MFIB_ITF_FLAG_FORWARD |
                                      MFIB_ITF_FLAG_ACCEPT |
                                      MFIB_ITF_FLAG_NEGATE_SIGNAL)));

    /*
     * update flags on the entry
     */
    mfib_table_entry_update(fib_index,
                            &pfx_1_1_1_1_c_239_1_1_1,
                            MFIB_SOURCE_API,
                            MFIB_ENTRY_FLAG_SIGNAL);
    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_SIGNAL,
                              3,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2,
                              DPO_ADJACENCY_MCAST, ai_3),
              "(1.1.1.1,239.1.1.1) replcaite ok");

    /*
     * remove paths
     */
    mfib_table_entry_path_remove(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if3);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_SIGNAL,
                              2,
                              DPO_ADJACENCY_MCAST, ai_1,
                              DPO_ADJACENCY_MCAST, ai_2),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[1]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    mfib_table_entry_path_remove(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if1);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_SIGNAL,
                              1,
                              DPO_ADJACENCY_MCAST, ai_2),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[0]->sw_if_index,
                                     MFIB_ITF_FLAG_ACCEPT));
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    /*
     * remove the accpeting only interface
     */
    mfib_table_entry_path_remove(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if0);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_SIGNAL,
                              1,
                              DPO_ADJACENCY_MCAST, ai_2),
              "(1.1.1.1,239.1.1.1) replcaite ok");
    MFIB_TEST_NS(mfib_test_entry_itf(mfei, tm->hw[2]->sw_if_index,
                                     MFIB_ITF_FLAG_FORWARD));
    MFIB_TEST_NS(mfib_test_entry_no_itf(mfei, tm->hw[0]->sw_if_index));
    MFIB_TEST_NS(mfib_test_entry_no_itf(mfei, tm->hw[1]->sw_if_index));
    MFIB_TEST_NS(mfib_test_entry_no_itf(mfei, tm->hw[3]->sw_if_index));

    /*
     * remove the last path, the entry still has flags so it remains
     */
    mfib_table_entry_path_remove(fib_index,
                                 &pfx_1_1_1_1_c_239_1_1_1,
                                 MFIB_SOURCE_API,
                                 &path_via_if2);

    MFIB_TEST(mfib_test_entry(mfei,
                              MFIB_ENTRY_FLAG_SIGNAL,
                              0),
              "(1.1.1.1,239.1.1.1) no replications");

    /*
     * update flags on the entry
     */
    mfib_table_entry_update(fib_index,
                            &pfx_1_1_1_1_c_239_1_1_1,
                            MFIB_SOURCE_API,
                            (MFIB_ENTRY_FLAG_SIGNAL |
                             MFIB_ENTRY_FLAG_CONNECTED));
    MFIB_TEST(mfib_test_entry(mfei,
                              (MFIB_ENTRY_FLAG_SIGNAL |
                               MFIB_ENTRY_FLAG_CONNECTED),
                              0),
              "(1.1.1.1,239.1.1.1) no replications");

    /*
     * remove flags on the entry. This is the last of the
     * state associated with the entry, so now it goes.
     */
    mfib_table_entry_update(fib_index,
                            &pfx_1_1_1_1_c_239_1_1_1,
                            MFIB_SOURCE_API,
                            MFIB_ENTRY_FLAG_NONE);
    mfei = mfib_table_lookup_exact_match(fib_index,
                                         &pfx_1_1_1_1_c_239_1_1_1);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei, "(1.1.1.1,239.1.1.1) gone");

    /*
     * remove the last path on 224.0.0.0/8 - the last entry
     */
    mfib_table_entry_path_remove(fib_index,
                                 &pfx_224_s_8,
                                 MFIB_SOURCE_API,
                                 &path_via_if0);

    mfei = mfib_table_lookup_exact_match(fib_index, &pfx_224_s_8);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei, "(224.0.0.0/8) gone");

    /*
     * hard delete the (*,232.1.1.1)
     */
    mfib_table_entry_delete(fib_index,
                            &pfx_239_1_1_1,
                            MFIB_SOURCE_API);

    mfei = mfib_table_lookup_exact_match(fib_index, &pfx_239_1_1_1);
    MFIB_TEST(FIB_NODE_INDEX_INVALID == mfei, "(*,232.1.1.1) gone");

    /*
     * Unlock the table - it's the last lock so should be gone thereafter
     */
    mfib_table_unlock(fib_index, FIB_PROTOCOL_IP4);

    MFIB_TEST((FIB_NODE_INDEX_INVALID ==
               mfib_table_find(FIB_PROTOCOL_IP4, fib_index)),
              "MFIB table %d gone", fib_index);

    adj_unlock(ai_1);
    adj_unlock(ai_2);
    adj_unlock(ai_3);

    /*
     * test we've leaked no resources
     */
    MFIB_TEST(0 == adj_mcast_db_size(), "0 MCAST adjs");
    MFIB_TEST(0 == pool_elts(replicate_pool), "0 replicates");
    MFIB_TEST(n_entries == pool_elts(mfib_entry_pool),
              " No more entries %d!=%d",
              n_entries, pool_elts(mfib_entry_pool));

}

static clib_error_t *
mfib_test (vlib_main_t * vm,
           unformat_input_t * input,
           vlib_cli_command_t * cmd_arg)
{
    mfib_test_mk_intf(4);

    mfib_test_v4();

    return (NULL);
}

VLIB_CLI_COMMAND (test_fib_command, static) = {
    .path = "test mfib",
    .short_help = "fib unit tests - DO NOT RUN ON A LIVE SYSTEM",
    .function = mfib_test,
};

clib_error_t *
mfib_test_init (vlib_main_t *vm)
{
    return 0;
}

VLIB_INIT_FUNCTION (mfib_test_init);
