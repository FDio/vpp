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


#include <vnet/mpls/mpls.h>
#include <vnet/bier/bier_table.h>
#include <vnet/bier/bier_entry.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_bit_string.h>
#include <vnet/bier/bier_imp.h>
#include <vnet/bier/bier_disp_table.h>
#include <vnet/bier/bier_disp_entry.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/mfib/mfib_table.h>

#include <vnet/fib/fib_test.h>

/*
 * Add debugs for passing tests
 */
static int bier_test_do_debug;

#define BIER_TEST_I(_cond, _comment, _args...)			\
({								\
    int _evald = (_cond);					\
    if (!(_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
    } else {							\
        if (bier_test_do_debug)                                 \
            fformat(stderr, "PASS:%d: " _comment "\n",          \
                    __LINE__, ##_args);				\
    }								\
    _evald;							\
})
#define BIER_TEST(_cond, _comment, _args...)			\
{								\
    if (!BIER_TEST_I(_cond, _comment, ##_args)) {		\
        return 1;                                               \
        ASSERT(!("FAIL: " _comment));				\
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

VNET_DEVICE_CLASS (test_interface_device_class,static) = {
  .name = "Test interface",
  .format_device_name = format_test_interface_name,
  .tx_function = dummy_interface_tx,
};

static u8 *hw_address;

static int
bier_test_mk_intf (u32 ninterfaces)
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

        BIER_TEST((NULL == error), "ADD interface %d", i);

        tm->hw[i] = vnet_get_hw_interface(vnet_get_main(),
                                          tm->hw_if_indicies[i]);
        vec_validate (ip4_main.fib_index_by_sw_if_index, tm->hw[i]->sw_if_index);
        vec_validate (ip6_main.fib_index_by_sw_if_index, tm->hw[i]->sw_if_index);
        ip4_main.fib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;
        ip6_main.fib_index_by_sw_if_index[tm->hw[i]->sw_if_index] = 0;
        error = vnet_sw_interface_set_flags(vnet_get_main(),
                                            tm->hw[i]->sw_if_index,
                                            VNET_SW_INTERFACE_FLAG_ADMIN_UP);
        BIER_TEST((NULL == error), "UP interface %d", i);
    }
    /*
     * re-eval after the inevitable realloc
     */
    for (i = 0; i < ninterfaces; i++)
    {
        tm->hw[i] = vnet_get_hw_interface(vnet_get_main(),
                                          tm->hw_if_indicies[i]);
    }

    return (0);
}

#define BIER_TEST_LB(_cond, _comment, _args...)			\
{								\
    if (!BIER_TEST_I(_cond, _comment, ##_args)) {		\
        return (0);						\
    }								\
}

static int
bier_test_validate_entry (index_t bei,
                          u16 n_buckets,
                          ...)
{
    dpo_id_t dpo = DPO_INVALID;
    const load_balance_t *lb;
    va_list ap;
    int res;

    va_start(ap, n_buckets);

    bier_entry_contribute_forwarding(bei, &dpo);

    BIER_TEST_LB((DPO_LOAD_BALANCE == dpo.dpoi_type),
                 "Entry links to %U",
                 format_dpo_type, dpo.dpoi_type);

    lb = load_balance_get(dpo.dpoi_index);
    res = fib_test_validate_lb_v(lb, n_buckets, &ap);

    dpo_reset(&dpo);

    va_end(ap);

    return (res);
}

static int
bier_test_mpls_spf (void)
{
    fib_node_index_t lfei, fei, bti;
    u32 mpls_fib_index;
    test_main_t *tm;
    int lb_count;

    lb_count = pool_elts(load_balance_pool);
    tm = &test_main;
#define N_BIER_ECMP_TABLES 16
    int ii;

    /*
     * Add the BIER Main table
     */
    const bier_table_id_t bt_0_0_0_256 = {
        .bti_set = 0,
        .bti_sub_domain = 0,
        .bti_hdr_len = BIER_HDR_LEN_256,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };

    bti = bier_table_add_or_lock(&bt_0_0_0_256, 1600);

    fib_test_lb_bucket_t l_o_bt[N_BIER_ECMP_TABLES];
    bier_table_id_t bt_ecmp_0_0_0_256 = bt_0_0_0_256;

    for (ii = 0; ii < N_BIER_ECMP_TABLES; ii++)
    {
        bt_ecmp_0_0_0_256.bti_ecmp = ii;

        l_o_bt[ii].type = FT_LB_BIER_TABLE;
        l_o_bt[ii].bier.table =
            bier_table_ecmp_create_and_lock(&bt_ecmp_0_0_0_256);
    };
    const fib_prefix_t pfx_1600_neos = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 1600,
        .fp_eos = MPLS_NON_EOS,
        .fp_payload_proto = DPO_PROTO_BIER,
    };
    const fib_prefix_t pfx_1600_eos = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 1600,
        .fp_eos = MPLS_EOS,
        .fp_payload_proto = DPO_PROTO_BIER,
    };

    mpls_fib_index = fib_table_find(FIB_PROTOCOL_MPLS,
                                    MPLS_FIB_DEFAULT_TABLE_ID);

    lfei = fib_table_lookup(mpls_fib_index, &pfx_1600_neos);
    BIER_TEST(FIB_NODE_INDEX_INVALID == lfei, "1600/0 is not present");

    lfei = fib_table_lookup(mpls_fib_index, &pfx_1600_eos);
    BIER_TEST(fib_test_validate_entry(lfei, FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      16,
                                      &l_o_bt[0],
                                      &l_o_bt[1],
                                      &l_o_bt[2],
                                      &l_o_bt[3],
                                      &l_o_bt[4],
                                      &l_o_bt[5],
                                      &l_o_bt[6],
                                      &l_o_bt[7],
                                      &l_o_bt[8],
                                      &l_o_bt[9],
                                      &l_o_bt[10],
                                      &l_o_bt[11],
                                      &l_o_bt[12],
                                      &l_o_bt[13],
                                      &l_o_bt[14],
                                      &l_o_bt[15]),
              "1600/1 LB stacks on BIER table %d", bti);

    /*
     * modify the table's local label - keep the lock count accurate
     */
    const fib_prefix_t pfx_1601_eos = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 1601,
        .fp_eos = MPLS_EOS,
        .fp_payload_proto = DPO_PROTO_BIER,
    };
    bti = bier_table_add_or_lock(&bt_0_0_0_256, 1601);
    bier_table_unlock(&bt_0_0_0_256);

    lfei = fib_table_lookup(mpls_fib_index, &pfx_1600_eos);
    BIER_TEST(FIB_NODE_INDEX_INVALID == lfei, "1600/1 is deleted");

    lfei = fib_table_lookup(mpls_fib_index, &pfx_1601_eos);
    BIER_TEST(fib_test_validate_entry(lfei, FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      16,
                                      &l_o_bt[0],
                                      &l_o_bt[1],
                                      &l_o_bt[2],
                                      &l_o_bt[3],
                                      &l_o_bt[4],
                                      &l_o_bt[5],
                                      &l_o_bt[6],
                                      &l_o_bt[7],
                                      &l_o_bt[8],
                                      &l_o_bt[9],
                                      &l_o_bt[10],
                                      &l_o_bt[11],
                                      &l_o_bt[12],
                                      &l_o_bt[13],
                                      &l_o_bt[14],
                                      &l_o_bt[15]),
              "1601/1 LB stacks on BIER table %d", bti);

    /*
     * add a route to the table. the via IP route does not exist.
     */
    const ip46_address_t nh_1_1_1_1 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x01010101),
        },
    };
    fib_route_path_t *paths_1_1_1_1 = NULL;
    fib_route_path_t path_1_1_1_1 = {
        .frp_addr = nh_1_1_1_1,
        .frp_bier_fib_index = bti,
        .frp_flags = FIB_ROUTE_PATH_BIER_FMASK,
    };
    vec_add1(path_1_1_1_1.frp_label_stack, 500);
    vec_add1(paths_1_1_1_1, path_1_1_1_1);
    const fib_prefix_t pfx_1_1_1_1_s_32 = {
        .fp_addr = nh_1_1_1_1,
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    };
    const bier_fmask_id_t bfm_id_1_1_1_1 = {
        .bfmi_hdr_type = BIER_HDR_O_MPLS,
        .bfmi_nh = nh_1_1_1_1,
    };
    index_t bei_1;

    bier_table_route_add(&bt_0_0_0_256, 1, paths_1_1_1_1);
    bei_1 = bier_table_lookup(bier_table_get(bti), 1);

    BIER_TEST((INDEX_INVALID != bei_1), "BP:1 present");

    /*
     * the newly created fmask should stack on the non-eos chain
     * of the via-fib-entry
     */
    dpo_id_t neos_dpo_1_1_1_1 = DPO_INVALID;
    bier_fmask_t *bfm_1_1_1_1;
    index_t bfmi_1_1_1_1;

    fei = fib_table_lookup_exact_match(0, &pfx_1_1_1_1_s_32);
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &neos_dpo_1_1_1_1);

    bfmi_1_1_1_1 = bier_fmask_db_find(bti, &bfm_id_1_1_1_1);
    bfm_1_1_1_1 = bier_fmask_get(bfmi_1_1_1_1);

    BIER_TEST(!dpo_cmp(&neos_dpo_1_1_1_1, &bfm_1_1_1_1->bfm_dpo),
              "Fmask via 1.1.1.1 stacks on neos from 1.1.1.1/32");

    /*
     * and that n-eos LB at this stage is a drop..
     */
    const fib_test_lb_bucket_t bucket_drop = {
        .type = FT_LB_DROP,
    };
    BIER_TEST(fib_test_validate_lb(&neos_dpo_1_1_1_1, 1, &bucket_drop),
             "1.1.1.1/32 n-eos LB 1 buckets via: DROP");

    /*
     * The BIER entry should stack on the forwarding chain of the fmask
     */
    const fib_test_lb_bucket_t dpo_o_bfm_1_1_1_1 = {
        .type = FT_LB_BIER_FMASK,
        .bier = {
            .fmask = bfmi_1_1_1_1,
        },
    };
    BIER_TEST(bier_test_validate_entry(bei_1, 1, &bucket_drop),
              "BP:1  stacks on bier drop");

    /*
     * give 1.1.1.1/32 a path and hence a interesting n-eos chain
     */
    ip46_address_t nh_10_10_10_1 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x0a0a0a01),
        },
    };
    adj_index_t ai_mpls_10_10_10_1;
    ai_mpls_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_10_1,
                                             tm->hw[0]->sw_if_index);

    fib_test_lb_bucket_t bucket_neos_99_via_10_10_10_1 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .label = 99,
            .eos = MPLS_NON_EOS,
            .adj = ai_mpls_10_10_10_1,
            .ttl = 255,
        },
    };
    mpls_label_t *out_lbl_99 = NULL;
    vec_add1(out_lbl_99, 99);

    fei = fib_table_entry_update_one_path(0,
                                          &pfx_1_1_1_1_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_10_1,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          out_lbl_99,
                                          FIB_ROUTE_PATH_FLAG_NONE);
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &neos_dpo_1_1_1_1);
    BIER_TEST(fib_test_validate_lb(&neos_dpo_1_1_1_1, 1,
                                   &bucket_neos_99_via_10_10_10_1),
              "1.1.1.1/32 n-eos LB 1 buckets via: 99 + 10.10.10.1");
    BIER_TEST(!dpo_cmp(&neos_dpo_1_1_1_1,
                       &bfm_1_1_1_1->bfm_dpo),
              "Fmask via 1.1.1.1 stacks on updated non-eos of 1.1.1.1/32");
    BIER_TEST(bier_test_validate_entry(bei_1, 1, &dpo_o_bfm_1_1_1_1),
              "BP:1  stacks on fmask 1.1.1.1");

    /*
     * add another path to the via entry.
     * this makes the via-entry instantiate a new load-balance with
     * 2 buckets. and the back-walk to the BIER entry will need to
     * re-stack on it.
     */
    ip46_address_t nh_10_10_10_2 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x0a0a0a02),
        },
    };
    adj_index_t ai_mpls_10_10_10_2;

    ai_mpls_10_10_10_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_10_2,
                                             tm->hw[0]->sw_if_index);

    fib_test_lb_bucket_t bucket_neos_100_via_10_10_10_2 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .label = 100,
            .eos = MPLS_NON_EOS,
            .adj = ai_mpls_10_10_10_2,
            .ttl = 255,
        },
    };
    mpls_label_t *out_lbl_100 = NULL;
    vec_add1(out_lbl_100, 100);

    fei = fib_table_entry_path_add(0,
                                   &pfx_1_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_2,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   out_lbl_100,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &neos_dpo_1_1_1_1);
    BIER_TEST(fib_test_validate_lb(&neos_dpo_1_1_1_1, 2,
                                   &bucket_neos_99_via_10_10_10_1,
                                   &bucket_neos_100_via_10_10_10_2),
              "1.1.1.1/32 n-eos LB 2 buckets "
              "via: 99 + 10.10.10.1, "
              "via: 100 + 10.10.10.2");
    BIER_TEST(!dpo_cmp(&neos_dpo_1_1_1_1,
                       &bfm_1_1_1_1->bfm_dpo),
              "Fmask via 1.1.1.1 stacks on updated non-eos of 1.1.1.1/32");

    /*
     * add another bier bit-position via the same next-hop
     * since its the same next hop, the two bit-positions should link
     * to the same fmask
     */
    index_t bei_2;

    bier_table_route_add(&bt_0_0_0_256, 2, paths_1_1_1_1);
    bei_2 = bier_table_lookup(bier_table_get(bti), 2);

    BIER_TEST(bier_test_validate_entry(bei_2, 1, &dpo_o_bfm_1_1_1_1),
              "BP:2 stacks on fmask 1.1.1.1");

    /*
     * now add a bit-position via a different next hop and expect to
     * link via a different fmask
     */
    const ip46_address_t nh_1_1_1_2 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x01010102),
        },
    };
    const fib_prefix_t pfx_1_1_1_2_s_32 = {
        .fp_addr = nh_1_1_1_2,
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    };
    fib_route_path_t *paths_1_1_1_2 = NULL, path_1_1_1_2 = {
        .frp_addr = nh_1_1_1_2,
        .frp_bier_fib_index = bti,
        .frp_flags = FIB_ROUTE_PATH_BIER_FMASK,
    };
    vec_add1(path_1_1_1_2.frp_label_stack, 501);
    vec_add1(paths_1_1_1_2, path_1_1_1_2);
    const bier_fmask_id_t bfm_id_1_1_1_2 = {
        .bfmi_hdr_type = BIER_HDR_O_MPLS,
        .bfmi_nh = nh_1_1_1_2,
    };
    index_t bei_3;

    mpls_label_t *out_lbl_101 = NULL;
    vec_add1(out_lbl_101, 101);
    fei = fib_table_entry_path_add(0,
                                   &pfx_1_1_1_2_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_2,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   out_lbl_101,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    bier_table_route_add(&bt_0_0_0_256, 3, paths_1_1_1_2);
    bei_3 = bier_table_lookup(bier_table_get(bti), 3);

    BIER_TEST((INDEX_INVALID != bei_3), "BP:3 present");

    /*
     * the newly created fmask should stack on the non-eos chain
     * of the via-fib-entry
     */
    dpo_id_t neos_dpo_1_1_1_2 = DPO_INVALID;
    bier_fmask_t *bfm_1_1_1_2;
    index_t bfmi_1_1_1_2;

    fei = fib_table_lookup_exact_match(0, &pfx_1_1_1_2_s_32);
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &neos_dpo_1_1_1_2);

    bfmi_1_1_1_2 = bier_fmask_db_find(bti, &bfm_id_1_1_1_2);
    bfm_1_1_1_2 = bier_fmask_get(bfmi_1_1_1_2);

    BIER_TEST(!dpo_cmp(&neos_dpo_1_1_1_2,
                       &bfm_1_1_1_2->bfm_dpo),
              "Fmask via 1.1.1.2 stacks on non-eos of 1.1.1.2/32");

    /*
     * The BIER entry should stack on the forwarding chain of the fmask
     */
    const fib_test_lb_bucket_t dpo_o_bfm_1_1_1_2 = {
        .type = FT_LB_BIER_FMASK,
        .bier = {
            .fmask = bfmi_1_1_1_2,
        },
    };
    BIER_TEST(bier_test_validate_entry(bei_3, 1, &dpo_o_bfm_1_1_1_2),
              "BP:3 stacks on fmask 1.1.1.2");

    /*
     * Load-balance BP:3 over both next-hops
     */
    bier_table_route_add(&bt_0_0_0_256, 3, paths_1_1_1_1);

    BIER_TEST(bier_test_validate_entry(bei_3, 2,
                                       &dpo_o_bfm_1_1_1_1,
                                       &dpo_o_bfm_1_1_1_2),
              "BP:3 stacks on fmask 1.1.1.2 & 1.1.1.1");

    /*
     * test that the ECMP choices for BP:3 have been spread over the
     * ECMP tables
     */
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[0].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:0 is 1.1.1.1");
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[1].bier.table), 3) ==
               bfmi_1_1_1_2),
              "fwd lookup for BP:3 ECMP:1 is 1.1.1.2");

    /*
     * Withdraw one of the via FIB and thus bring down the fmask
     * expect the bier0entry forwarding to remove this from the set
     */
    fib_table_entry_delete(0, &pfx_1_1_1_2_s_32, FIB_SOURCE_API);

    BIER_TEST(bier_test_validate_entry(bei_3, 1,
                                       &dpo_o_bfm_1_1_1_1),
              "BP:3 post 1.1.1.2 removal stacks on fmask 1.1.1.1");

    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[0].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:0 is 1.1.1.1");
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[1].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:1 is 1.1.1.1");

    /*
     * add the via back
     */
    out_lbl_101 = NULL;
    vec_add1(out_lbl_101, 101);
    fei = fib_table_entry_path_add(0,
                                   &pfx_1_1_1_2_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_2,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   out_lbl_101,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    /* suspend so the update walk kicks int */
    vlib_process_suspend(vlib_get_main(), 1e-5);

    BIER_TEST(bier_test_validate_entry(bei_3, 2,
                                       &dpo_o_bfm_1_1_1_1,
                                       &dpo_o_bfm_1_1_1_2),
              "BP:3 stacks on fmask 1.1.1.2 & 1.1.1.1");
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[0].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:0 is 1.1.1.1");
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[1].bier.table), 3) ==
               bfmi_1_1_1_2),
              "fwd lookup for BP:3 ECMP:1 is 1.1.1.2");

    /*
     * remove the original 1.1.1.2 fmask from BP:3
     */
    bier_table_route_remove(&bt_0_0_0_256, 3, paths_1_1_1_2);
    BIER_TEST(bier_test_validate_entry(bei_3, 1,
                                       &dpo_o_bfm_1_1_1_1),
              "BP:3 stacks on fmask 1.1.1.1");
    /*
     * test that the ECMP choices for BP:3 have been updated
     */
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[0].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:0 is 1.1.1.1");
    BIER_TEST((bier_table_fwd_lookup(bier_table_get(l_o_bt[1].bier.table), 3) ==
               bfmi_1_1_1_1),
              "fwd lookup for BP:3 ECMP:1 is 1.1.1.1");

    /*
     * remove the routes added
     */
    bier_table_route_remove(&bt_0_0_0_256, 2, paths_1_1_1_1);
    bier_table_route_remove(&bt_0_0_0_256, 3, paths_1_1_1_2);
    bier_table_route_remove(&bt_0_0_0_256, 3, paths_1_1_1_1);
    bier_table_route_remove(&bt_0_0_0_256, 1, paths_1_1_1_1);


    /*
     * delete the table
     */
    bier_table_unlock(&bt_0_0_0_256);

    /*
     * test resources are freed
     */
    for (ii = 0; ii < N_BIER_ECMP_TABLES; ii++)
    {
        bier_table_ecmp_unlock(l_o_bt[ii].bier.table);
    };
    BIER_TEST(0 == pool_elts(bier_table_pool), "BIER table pool empty");
    BIER_TEST(0 == pool_elts(bier_fmask_pool), "BIER fmask pool empty");
    BIER_TEST(0 == pool_elts(bier_entry_pool), "BIER entry pool empty");

    adj_unlock(ai_mpls_10_10_10_1);
    adj_unlock(ai_mpls_10_10_10_2);
    dpo_reset(&neos_dpo_1_1_1_1);
    dpo_reset(&neos_dpo_1_1_1_2);
    fib_table_entry_delete(0, &pfx_1_1_1_1_s_32, FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_1_1_1_2_s_32, FIB_SOURCE_API);

    /* +1 to account for the one time alloc'd drop LB in the MPLS fibs */
    BIER_TEST(lb_count+1 == pool_elts(load_balance_pool),
              "Load-balance resources freed ");
    BIER_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    vec_free(paths_1_1_1_1);
    vec_free(paths_1_1_1_2);

    return (0);
}

static int
bier_test_mpls_imp (void)
{
    fib_node_index_t bii;
    /* test_main_t *tm; */

    /* tm = &test_main; */

    /*
     * Add the BIER Main table
     */
    const bier_table_id_t bt_0_0_0_256 = {
        .bti_set = 0,
        .bti_sub_domain = 0,
        .bti_hdr_len = BIER_HDR_LEN_256,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };

    bier_table_add_or_lock(&bt_0_0_0_256, 1600);

    /*
     * A bit-string for imp 1.
     */
    bier_bit_string_t bbs_256;
    u8 buckets[BIER_HDR_BUCKETS_256];
    memset(buckets, 0x5, BIER_HDR_BUCKETS_256);

    bier_bit_string_init(&bbs_256, BIER_HDR_LEN_256, buckets);

    bii = bier_imp_add_or_lock(&bt_0_0_0_256, 1, &bbs_256);

    /*
     * An mfib entry that resolves via the BIER imposition
     */
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
    fib_route_path_t path_via_bier_imp_1 = {
        .frp_proto = DPO_PROTO_BIER,
        .frp_bier_imp = bii,
        .frp_weight = 0,
        .frp_flags = FIB_ROUTE_PATH_BIER_IMP,
    };
    mfib_table_entry_path_update(0, // default table
                                 &pfx_1_1_1_1_c_239_1_1_1 ,
                                 MFIB_SOURCE_API,
                                 &path_via_bier_imp_1,
                                 MFIB_ITF_FLAG_FORWARD);
    mfib_table_entry_delete(0,
                            &pfx_1_1_1_1_c_239_1_1_1 ,
                            MFIB_SOURCE_API);

    bier_imp_unlock(bii);
    bier_table_unlock(&bt_0_0_0_256);

    BIER_TEST(0 == pool_elts(bier_imp_pool),
              "BIER imposition resources freed ");
    BIER_TEST(0 == pool_elts(bier_table_pool),
              "BIER table resources freed ");

    return (0);
}

static int
bier_test_mpls_disp (void)
{
    /* test_main_t *tm; */

    /* tm = &test_main; */

    /*
     * Add the BIER Main table
     */
    const bier_table_id_t bt_0_0_0_256 = {
        .bti_set = 0,
        .bti_sub_domain = 0,
        .bti_hdr_len = BIER_HDR_LEN_256,
        .bti_type = BIER_TABLE_MPLS_SPF,
        .bti_ecmp = BIER_ECMP_TABLE_ID_MAIN,
    };
    index_t bti;

    bti = bier_table_add_or_lock(&bt_0_0_0_256, 1600);

    /*
     * Add a BIER dispoition table
     */
    const u32 bier_disp_tbl_id = 1;
    index_t bdti1;

    bdti1 = bier_disp_table_add_or_lock(bier_disp_tbl_id);

    /*
     * add a bit-poistion in the table that resolves via
     * DISP table, i.e. a for-us bit-position
     */
    fib_route_path_t *paths_via_disp = NULL, path_via_disp = {
        // .frp_addr = all-zeros
        .frp_bier_fib_index = bdti1,
        .frp_flags = FIB_ROUTE_PATH_BIER_FMASK,
    };
    vec_add1(paths_via_disp, path_via_disp);

    bier_table_route_add(&bt_0_0_0_256, 3, paths_via_disp);

    /*
     * the fmask should stack on the BIER disp table
     */
    const bier_fmask_id_t bfm_id_0_0_0_0 = {
        .bfmi_hdr_type = BIER_HDR_O_MPLS,
    };
    bier_fmask_t *bfm_0_0_0_0;
    index_t bfmi_0_0_0_0;
    dpo_id_t dpo_disp_tbl_1 = DPO_INVALID;

    bier_disp_table_contribute_forwarding(bdti1, &dpo_disp_tbl_1);

    bfmi_0_0_0_0 = bier_fmask_db_find(bti, &bfm_id_0_0_0_0);
    bfm_0_0_0_0 = bier_fmask_get(bfmi_0_0_0_0);

    BIER_TEST(!dpo_cmp(&dpo_disp_tbl_1, &bfm_0_0_0_0->bfm_dpo),
              "Fmask via 0.0.0.0 stacks on BIER disp table 1");

    /*
     * and a deag entry into the disposition table
     */
    fib_route_path_t *rpaths = NULL, path_via_mfib = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_addr = zero_addr,
        .frp_fib_index = 0, // default MFIB table
        .frp_rpf_id = 9, // some non-zero value
        .frp_flags = FIB_ROUTE_PATH_RPF_ID,
    };
    bier_hdr_src_id_t src = 99;
    vec_add1(rpaths, path_via_mfib);
    bier_disp_table_entry_path_add(bier_disp_tbl_id, src,
                                   BIER_HDR_PROTO_IPV4, rpaths);

    /* which should stack on a lookup in the mfib table */
    const dpo_id_t *dpo_disp_entry_lb;
    const dpo_id_t *dpo_disp_entry_v4;
    bier_disp_entry_t *bde_99;
    index_t bdei;

    bdei = bier_disp_table_lookup(bdti1, clib_host_to_net_u16(src));
    bde_99 = bier_disp_entry_get(bdei);
    dpo_disp_entry_lb = &bde_99->bde_fwd[BIER_HDR_PROTO_IPV4].bde_dpo;

    BIER_TEST(dpo_disp_entry_lb->dpoi_type == DPO_LOAD_BALANCE,
              "BIER Disp entry stacks on LB");

    load_balance_t *lb;
    lb = load_balance_get(dpo_disp_entry_lb->dpoi_index);
    dpo_disp_entry_v4 = load_balance_get_bucket_i(lb, 0);

    lookup_dpo_t *lkd = lookup_dpo_get(dpo_disp_entry_v4->dpoi_index);

    BIER_TEST((bdti1 == lkd->lkd_fib_index),
              "disp is deag in %d %U",
              lkd->lkd_fib_index,
              format_dpo_id, dpo_disp_entry_v4, 0);
    BIER_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
              "disp is destination deag in %d %U",
              lkd->lkd_input,
              format_dpo_id, dpo_disp_entry_v4, 0);
    BIER_TEST((LOOKUP_MULTICAST == lkd->lkd_cast),
              "disp is multicast deag in %d %U",
              lkd->lkd_input,
              format_dpo_id, dpo_disp_entry_v4, 0);

    /*
     * cleanup
     */
    dpo_reset(&dpo_disp_tbl_1);

    bier_disp_table_entry_path_remove(bier_disp_tbl_id, src,
                                      BIER_HDR_PROTO_IPV4, rpaths);
    bier_table_route_remove(&bt_0_0_0_256, 3, paths_via_disp);

    bier_disp_table_unlock_w_table_id(bier_disp_tbl_id);

    bier_table_unlock(&bt_0_0_0_256);

    BIER_TEST(0 == pool_elts(bier_fmask_pool),
              "BIER fmask resources freed ");
    BIER_TEST(0 == pool_elts(bier_table_pool),
              "BIER table resources freed ");
    BIER_TEST(0 == pool_elts(bier_disp_table_pool),
              "BIER Disposition table resources freed ");
    BIER_TEST(0 == pool_elts(bier_disp_entry_pool),
              "BIER Disposition entry resources freed ");

    vec_free(paths_via_disp);
    return (0);
}

static clib_error_t *
bier_test (vlib_main_t * vm,
           unformat_input_t * input,
           vlib_cli_command_t * cmd_arg)
{
    int res = 0;

    res += bier_test_mk_intf(4);

    if (unformat (input, "debug"))
    {
        bier_test_do_debug = 1;
    }

    if (unformat (input, "mid"))
        res += bier_test_mpls_spf();
    else if (unformat (input, "head"))
        res += bier_test_mpls_imp();
    else if (unformat (input, "tail"))
        res += bier_test_mpls_disp();
    else
    {
        res += bier_test_mpls_spf();
        res += bier_test_mpls_imp();
        res += bier_test_mpls_disp();
    }

    if (res)
    {
        return clib_error_return(0, "BIER Unit Test Failed");
    }
    else
    {
        return (NULL);
    }
}

VLIB_CLI_COMMAND (test_route_command, static) = {
    .path = "test bier",
    .short_help = "bier unit tests",
    .function = bier_test,
};

clib_error_t *
bier_test_init (vlib_main_t *vm)
{
    return 0;
}

VLIB_INIT_FUNCTION (bier_test_init);
