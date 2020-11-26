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

#include <vnet/fib/fib_test.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <vnet/dpo/mpls_label_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/receive_dpo.h>
#include <vnet/dpo/ip_null_dpo.h>
#include <vnet/bfd/bfd_main.h>
#include <vnet/dpo/interface_rx_dpo.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/dpo/dvr_dpo.h>
#include <vnet/dpo/mpls_disposition.h>
#include <vnet/dpo/punt_dpo.h>

#include <vnet/mpls/mpls.h>

#include <vnet/fib/fib_test.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_node_list.h>
#include <vnet/fib/fib_urpf_list.h>

#include <vlib/unix/plugin.h>

/*
 * Add debugs for passing tests
 */
static int fib_test_do_debug;

#define FIB_TEST_I(_cond, _comment, _args...)			\
({								\
    int _evald = (_cond);					\
    if (!(_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
        res = 1;                                                \
    } else {							\
        if (fib_test_do_debug)                                  \
            fformat(stderr, "PASS:%d: " _comment "\n",          \
                    __LINE__, ##_args);				\
    }								\
    res;							\
})
#define FIB_TEST(_cond, _comment, _args...)			\
{								\
    if (FIB_TEST_I(_cond, _comment, ##_args)) {                 \
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

static uword placeholder_interface_tx (vlib_main_t * vm,
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
    .tx_function = placeholder_interface_tx,
    .admin_up_down_function = test_interface_admin_up_down,
};

static u8 *hw_address;

static int
fib_test_mk_intf (u32 ninterfaces)
{
    clib_error_t * error = NULL;
    test_main_t *tm = &test_main;
    u32 i, res;
    u8 byte;

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

        FIB_TEST((NULL == error), "ADD interface %d", i);

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

        error = vnet_sw_interface_set_flags(vnet_get_main(),
                                            tm->hw[i]->sw_if_index,
                                            VNET_SW_INTERFACE_FLAG_ADMIN_UP);
        FIB_TEST((NULL == error), "UP interface %d", i);
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

#define FIB_TEST_REC_FORW(_rec_prefix, _via_prefix, _bucket)		\
    {                                                                   \
        const dpo_id_t *_rec_dpo = fib_entry_contribute_ip_forwarding(  \
            fib_table_lookup_exact_match(fib_index, (_rec_prefix)));    \
        const dpo_id_t *_via_dpo = fib_entry_contribute_ip_forwarding(  \
            fib_table_lookup(fib_index, (_via_prefix)));                \
        FIB_TEST(!dpo_cmp(_via_dpo,                                     \
                          load_balance_get_bucket(_rec_dpo->dpoi_index,	\
                                                  _bucket)),		\
                 "%U is recursive via %U",                              \
                 format_fib_prefix, (_rec_prefix),                      \
                 format_fib_prefix, _via_prefix);                       \
    }

#define FIB_TEST_LB_BUCKET_VIA_ADJ(_prefix, _bucket, _ai)               \
    {                                                                   \
     const dpo_id_t *_dpo = fib_entry_contribute_ip_forwarding(         \
                                                               fib_table_lookup_exact_match(fib_index, (_prefix))); \
     const dpo_id_t *_dpo1 =                                            \
         load_balance_get_bucket(_dpo->dpoi_index, _bucket);            \
     FIB_TEST(DPO_ADJACENCY == _dpo1->dpoi_type, "type is %U",          \
                  format_dpo_type, _dpo1->dpoi_type);                   \
     FIB_TEST((_ai == _dpo1->dpoi_index),                               \
                  "%U bucket %d resolves via %U",                       \
                  format_fib_prefix, (_prefix),                         \
                  _bucket,                                              \
                  format_dpo_id, _dpo1, 0);                             \
     }

#define FIB_TEST_RPF(_cond, _comment, _args...)         \
    {                                                   \
        if (FIB_TEST_I(_cond, _comment, ##_args)) {     \
            res = 1;                                    \
            goto cleanup;                               \
        }                                               \
    }

static int
fib_test_urpf_is_equal (fib_node_index_t fei,
                        fib_forward_chain_type_t fct,
                        u32 num, ...)
{
    dpo_id_t dpo = DPO_INVALID;
    fib_urpf_list_t *urpf;
    int ii, res;
    index_t ui;
    va_list ap;

    va_start(ap, num);

    res = 0;
    fib_entry_contribute_forwarding(fei, fct, &dpo);
    ui = load_balance_get_urpf(dpo.dpoi_index);

    urpf = fib_urpf_list_get(ui);

    FIB_TEST_RPF(num == vec_len(urpf->furpf_itfs),
                 "RPF:%U len %d == %d",
                 format_fib_urpf_list, ui,
                 num, vec_len(urpf->furpf_itfs));
    FIB_TEST_RPF(num == fib_urpf_check_size(ui),
                 "RPF:%U check-size %d == %d",
                 format_fib_urpf_list, ui,
                 num, vec_len(urpf->furpf_itfs));

    for (ii = 0; ii < num; ii++)
    {
        adj_index_t ai = va_arg(ap, adj_index_t);

        FIB_TEST_RPF(ai == urpf->furpf_itfs[ii],
                     "RPF:%d item:%d - %d == %d",
                     ui, ii, ai, urpf->furpf_itfs[ii]);
        FIB_TEST_RPF(fib_urpf_check(ui, ai),
                     "RPF:%d %d found",
                     ui, ai);
    }

    dpo_reset(&dpo);

cleanup:
    va_end(ap);

    return (res);
}

static u8*
fib_test_build_rewrite (u8 *eth_addr)
{
    u8* rewrite = NULL;

    vec_validate(rewrite, 13);

    memcpy(rewrite, eth_addr, 6);
    memcpy(rewrite+6, eth_addr, 6);

    return (rewrite);
}

#define FIB_TEST_LB(_cond, _comment, _args...)          \
    {                                                   \
        if (FIB_TEST_I(_cond, _comment, ##_args)) {     \
            return (1);                                 \
        }                                               \
    }

int
fib_test_validate_rep_v (const replicate_t *rep,
                         u16 n_buckets,
                         va_list *ap)
{
    const fib_test_rep_bucket_t *exp;
    const dpo_id_t *dpo;
    int bucket, res;

    res = 0;
    FIB_TEST_LB((n_buckets == rep->rep_n_buckets),
                "n_buckets = %d", rep->rep_n_buckets);

    for (bucket = 0; bucket < n_buckets; bucket++)
    {
        exp = va_arg(*ap, fib_test_rep_bucket_t*);

        dpo = replicate_get_bucket_i(rep, bucket);

        switch (exp->type)
        {
        case FT_REP_LABEL_O_ADJ:
            {
                const mpls_label_dpo_t *mld;
                mpls_label_t hdr;

		FIB_TEST_LB((mpls_label_dpo_get_type(MPLS_LABEL_DPO_FLAG_NONE)
                             == dpo->dpoi_type),
                            "bucket %d stacks on %U",
                            bucket,
                            format_dpo_type, dpo->dpoi_type);

                mld = mpls_label_dpo_get(dpo->dpoi_index);
                hdr = clib_net_to_host_u32(mld->mld_hdr[0].label_exp_s_ttl);

                FIB_TEST_LB((vnet_mpls_uc_get_label(hdr) ==
                             exp->label_o_adj.label),
                            "bucket %d stacks on label %d",
                            bucket,
                            exp->label_o_adj.label);

                FIB_TEST_LB((vnet_mpls_uc_get_s(hdr) ==
                             exp->label_o_adj.eos),
                            "bucket %d stacks on label %d %U",
                            bucket,
                            exp->label_o_adj.label,
                            format_mpls_eos_bit, exp->label_o_adj.eos);

                FIB_TEST_LB((DPO_ADJACENCY_INCOMPLETE == mld->mld_dpo.dpoi_type),
                            "bucket %d label stacks on %U",
                            bucket,
                            format_dpo_type, mld->mld_dpo.dpoi_type);

                FIB_TEST_LB((exp->label_o_adj.adj == mld->mld_dpo.dpoi_index),
                            "bucket %d label stacks on adj %d",
                            bucket,
                            exp->label_o_adj.adj);
            }
            break;
        case FT_REP_INTF:
            FIB_TEST_LB((DPO_INTERFACE_RX == dpo->dpoi_type),
                        "bucket %d stacks on %U",
                        bucket,
                        format_dpo_type, dpo->dpoi_type);

            FIB_TEST_LB((exp->adj.adj == dpo->dpoi_index),
                        "bucket %d stacks on adj %d",
                        bucket,
                        exp->adj.adj);
            break;
        case FT_REP_DISP_MFIB_LOOKUP:
//            ASSERT(0);
            break;
        }
    }

    return (res);
}

int
fib_test_validate_lb_v (const load_balance_t *lb,
                        int n_buckets,
                        va_list *ap)
{
    const dpo_id_t *dpo;
    int bucket, res;

    res = 0;
    FIB_TEST_LB((n_buckets == lb->lb_n_buckets), "n_buckets = %d", lb->lb_n_buckets);

    for (bucket = 0; bucket < n_buckets; bucket++)
    {
        const fib_test_lb_bucket_t *exp;

        exp = va_arg(*ap, fib_test_lb_bucket_t*);
        dpo = load_balance_get_bucket_i(lb, bucket);

	switch (exp->type)
	{
	case FT_LB_LABEL_STACK_O_ADJ:
	    {
		const mpls_label_dpo_t *mld;
                mpls_label_dpo_flags_t mf;
                mpls_label_t hdr;
		u32 ii;

                mf = ((exp->label_stack_o_adj.mode ==
                       FIB_MPLS_LSP_MODE_UNIFORM) ?
                      MPLS_LABEL_DPO_FLAG_UNIFORM_MODE :
                      MPLS_LABEL_DPO_FLAG_NONE);
		FIB_TEST_LB((mpls_label_dpo_get_type(mf) == dpo->dpoi_type),
			   "bucket %d stacks on %U",
			   bucket,
			   format_dpo_type, dpo->dpoi_type);

		mld = mpls_label_dpo_get(dpo->dpoi_index);

		FIB_TEST_LB(exp->label_stack_o_adj.label_stack_size == mld->mld_n_labels,
			    "label stack size",
			    mld->mld_n_labels);

		for (ii = 0; ii < mld->mld_n_labels; ii++)
		{
		    hdr = clib_net_to_host_u32(mld->mld_hdr[ii].label_exp_s_ttl);
		    FIB_TEST_LB((vnet_mpls_uc_get_label(hdr) ==
				 exp->label_stack_o_adj.label_stack[ii]),
				"bucket %d stacks on label %d",
				bucket,
				exp->label_stack_o_adj.label_stack[ii]);

		    if (ii == mld->mld_n_labels-1)
		    {
			FIB_TEST_LB((vnet_mpls_uc_get_s(hdr) ==
				     exp->label_o_adj.eos),
				    "bucket %d stacks on label %d %U!=%U",
				    bucket,
				    exp->label_stack_o_adj.label_stack[ii],
				    format_mpls_eos_bit, exp->label_o_adj.eos,
				    format_mpls_eos_bit, vnet_mpls_uc_get_s(hdr));
		    }
		    else
		    {
			FIB_TEST_LB((vnet_mpls_uc_get_s(hdr) == MPLS_NON_EOS),
				    "bucket %d stacks on label %d %U",
				    bucket,
				    exp->label_stack_o_adj.label_stack[ii],
				    format_mpls_eos_bit, vnet_mpls_uc_get_s(hdr));
		    }
		}

		FIB_TEST_LB((DPO_ADJACENCY_INCOMPLETE == mld->mld_dpo.dpoi_type),
			    "bucket %d label stacks on %U",
			    bucket,
			    format_dpo_type, mld->mld_dpo.dpoi_type);

		FIB_TEST_LB((exp->label_stack_o_adj.adj == mld->mld_dpo.dpoi_index),
			    "bucket %d label stacks on adj %d",
			    bucket,
			    exp->label_stack_o_adj.adj);
	    }
	    break;
	case FT_LB_LABEL_O_ADJ:
	    {
		const mpls_label_dpo_t *mld;
                mpls_label_t hdr;
		FIB_TEST_LB((mpls_label_dpo_get_type(MPLS_LABEL_DPO_FLAG_NONE)
                             == dpo->dpoi_type),
			   "bucket %d stacks on %U",
			   bucket,
			   format_dpo_type, dpo->dpoi_type);

		mld = mpls_label_dpo_get(dpo->dpoi_index);
                hdr = clib_net_to_host_u32(mld->mld_hdr[0].label_exp_s_ttl);

		FIB_TEST_LB((vnet_mpls_uc_get_label(hdr) ==
			     exp->label_o_adj.label),
			    "bucket %d stacks on label %d",
			    bucket,
			    exp->label_o_adj.label);

		FIB_TEST_LB((vnet_mpls_uc_get_s(hdr) ==
			     exp->label_o_adj.eos),
			    "bucket %d stacks on label %d %U",
			    bucket,
			    exp->label_o_adj.label,
			    format_mpls_eos_bit, exp->label_o_adj.eos);

		FIB_TEST_LB((DPO_ADJACENCY_INCOMPLETE == mld->mld_dpo.dpoi_type),
			    "bucket %d label stacks on %U",
			    bucket,
			    format_dpo_type, mld->mld_dpo.dpoi_type);

		FIB_TEST_LB((exp->label_o_adj.adj == mld->mld_dpo.dpoi_index),
			    "bucket %d label stacks on adj %d",
			    bucket,
			    exp->label_o_adj.adj);
	    }
	    break;
	case FT_LB_LABEL_O_LB:
	    {
		const mpls_label_dpo_t *mld;
                mpls_label_dpo_flags_t mf;
                mpls_label_t hdr;

                mf = ((exp->label_o_lb.mode ==
                       FIB_MPLS_LSP_MODE_UNIFORM) ?
                      MPLS_LABEL_DPO_FLAG_UNIFORM_MODE :
                      MPLS_LABEL_DPO_FLAG_NONE);
		FIB_TEST_LB((mpls_label_dpo_get_type(mf) == dpo->dpoi_type),
			   "bucket %d stacks on %U",
			   bucket,
			   format_dpo_type, dpo->dpoi_type);

		mld = mpls_label_dpo_get(dpo->dpoi_index);
                hdr = clib_net_to_host_u32(mld->mld_hdr[0].label_exp_s_ttl);

		FIB_TEST_LB(1 == mld->mld_n_labels, "label stack size",
			    mld->mld_n_labels);
		FIB_TEST_LB((vnet_mpls_uc_get_label(hdr) ==
			     exp->label_o_lb.label),
			    "bucket %d stacks on label %d",
			    bucket,
			    exp->label_o_lb.label);

		FIB_TEST_LB((vnet_mpls_uc_get_s(hdr) ==
			     exp->label_o_lb.eos),
			    "bucket %d stacks on label %d %U",
			    bucket,
			    exp->label_o_lb.label,
			    format_mpls_eos_bit, exp->label_o_lb.eos);

		FIB_TEST_LB((DPO_LOAD_BALANCE == mld->mld_dpo.dpoi_type),
			    "bucket %d label stacks on %U",
			    bucket,
			    format_dpo_type, mld->mld_dpo.dpoi_type);

		FIB_TEST_LB((exp->label_o_lb.lb == mld->mld_dpo.dpoi_index),
			    "bucket %d label stacks on LB %d",
			    bucket,
			    exp->label_o_lb.lb);
	    }
	    break;
	case FT_LB_ADJ:
	    res = FIB_TEST_I(((DPO_ADJACENCY == dpo->dpoi_type) ||
                              (DPO_ADJACENCY_INCOMPLETE == dpo->dpoi_type)),
                             "bucket %d stacks on %U",
                             bucket,
                             format_dpo_type, dpo->dpoi_type);
	    FIB_TEST_LB((exp->adj.adj == dpo->dpoi_index),
			"bucket %d stacks on adj %d",
			bucket,
			exp->adj.adj);
	    break;
	case FT_LB_MPLS_DISP_PIPE_O_ADJ:
        {
            const mpls_disp_dpo_t *mdd;

            res = FIB_TEST_I((DPO_MPLS_DISPOSITION_PIPE == dpo->dpoi_type),
		       "bucket %d stacks on %U",
		       bucket,
		       format_dpo_type, dpo->dpoi_type);

            mdd = mpls_disp_dpo_get(dpo->dpoi_index);

            dpo = &mdd->mdd_dpo;

	    res = FIB_TEST_I(((DPO_ADJACENCY == dpo->dpoi_type) ||
                              (DPO_ADJACENCY_INCOMPLETE == dpo->dpoi_type)),
                            "bucket %d stacks on %U",
                             bucket,
                             format_dpo_type, dpo->dpoi_type);
	    FIB_TEST_LB((exp->adj.adj == dpo->dpoi_index),
			"bucket %d stacks on adj %d",
			bucket,
			exp->adj.adj);
	    break;
        }
	case FT_LB_INTF:
	    res = FIB_TEST_I((DPO_INTERFACE_RX == dpo->dpoi_type),
                             "bucket %d stacks on %U",
                             bucket,
                             format_dpo_type, dpo->dpoi_type);
	    FIB_TEST_LB((exp->adj.adj == dpo->dpoi_index),
			"bucket %d stacks on adj %d",
			bucket,
			exp->adj.adj);
	    break;
	case FT_LB_L2:
	    res = FIB_TEST_I((DPO_DVR == dpo->dpoi_type),
                             "bucket %d stacks on %U",
                             bucket,
                             format_dpo_type, dpo->dpoi_type);
	    FIB_TEST_LB((exp->adj.adj == dpo->dpoi_index),
			"bucket %d stacks on adj %d",
			bucket,
			exp->adj.adj);
	    break;
	case FT_LB_O_LB:
	    res = FIB_TEST_I((DPO_LOAD_BALANCE == dpo->dpoi_type),
                             "bucket %d stacks on %U",
                             bucket,
                             format_dpo_type, dpo->dpoi_type);
            FIB_TEST_LB((exp->lb.lb == dpo->dpoi_index),
                        "bucket %d stacks on lb %d not %d",
                        bucket,
                        dpo->dpoi_index,
                        exp->lb.lb);
            break;
        case FT_LB_BIER_TABLE:
            FIB_TEST_LB((DPO_BIER_TABLE == dpo->dpoi_type),
                        "bucket %d stacks on %U",
                        bucket,
                        format_dpo_type, dpo->dpoi_type);
            FIB_TEST_LB((exp->bier.table == dpo->dpoi_index),
                        "bucket %d stacks on lb %d",
                        bucket,
                        exp->bier.table);
            break;
        case FT_LB_BIER_FMASK:
            FIB_TEST_LB((DPO_BIER_FMASK == dpo->dpoi_type),
                        "bucket %d stacks on %U",
                        bucket,
                        format_dpo_type, dpo->dpoi_type);
            FIB_TEST_LB((exp->bier.fmask == dpo->dpoi_index),
                        "bucket %d stacks on lb %d",
                        bucket,
                        exp->bier.fmask);
            break;
        case FT_LB_DROP:
            FIB_TEST_LB((DPO_DROP == dpo->dpoi_type),
                        "bucket %d stacks on %U",
                        bucket,
                        format_dpo_type, dpo->dpoi_type);
            break;
        case FT_LB_PUNT:
            FIB_TEST_LB((DPO_PUNT == dpo->dpoi_type),
                        "bucket %d stacks on %U",
                        bucket,
                        format_dpo_type, dpo->dpoi_type);
            break;
        }
    }
    return (res);
}

int
fib_test_validate_lb (const dpo_id_t *dpo,
                      int n_buckets,
                      ...)
{
    const load_balance_t *lb;
    va_list ap;
    int res;

    res = 0;
    va_start(ap, n_buckets);

    if (!FIB_TEST_I((DPO_LOAD_BALANCE == dpo->dpoi_type),
                    "Entry links to %U",
                    format_dpo_type, dpo->dpoi_type))
    {
        lb = load_balance_get(dpo->dpoi_index);

        res = fib_test_validate_lb_v(lb, n_buckets, &ap);
    }
    else
    {
        res = 1;
    }

    va_end(ap);

    return (res);
}

int
fib_test_validate_entry (fib_node_index_t fei,
                         fib_forward_chain_type_t fct,
                         int n_buckets,
                         ...)
{
    dpo_id_t dpo = DPO_INVALID;
    const fib_prefix_t *pfx;
    index_t fw_lbi;
    u32 fib_index;
    va_list ap;
    int res;


    res = 0;
    pfx = fib_entry_get_prefix(fei);
    fib_index = fib_entry_get_fib_index(fei);
    fib_entry_contribute_forwarding(fei, fct, &dpo);

    if (DPO_REPLICATE == dpo.dpoi_type)
    {
        const replicate_t *rep;

        va_start(ap, n_buckets);
        rep = replicate_get(dpo.dpoi_index);
        res = fib_test_validate_rep_v(rep, n_buckets, &ap);
        va_end (ap);
    }
    else
    {
        const load_balance_t *lb;

        FIB_TEST_LB((DPO_LOAD_BALANCE == dpo.dpoi_type),
                    "%U Entry links to %U",
                    format_fib_prefix, pfx,
                    format_dpo_type, dpo.dpoi_type);

        va_start(ap, n_buckets);
        lb = load_balance_get(dpo.dpoi_index);
        res = fib_test_validate_lb_v(lb, n_buckets, &ap);
        va_end(ap);

        /*
         * ensure that the LB contributed by the entry is the
         * same as the LB in the forwarding tables
         */
        if (fct == fib_entry_get_default_chain_type(fib_entry_get(fei)))
        {
            switch (pfx->fp_proto)
            {
            case FIB_PROTOCOL_IP4:
                fw_lbi = ip4_fib_forwarding_lookup(fib_index, &pfx->fp_addr.ip4);
                break;
            case FIB_PROTOCOL_IP6:
                fw_lbi = ip6_fib_table_fwding_lookup(fib_index, &pfx->fp_addr.ip6);
                break;
            case FIB_PROTOCOL_MPLS:
                {
                    mpls_unicast_header_t hdr = {
                        .label_exp_s_ttl = 0,
                    };

                    vnet_mpls_uc_set_label(&hdr.label_exp_s_ttl, pfx->fp_label);
                    vnet_mpls_uc_set_s(&hdr.label_exp_s_ttl, pfx->fp_eos);
                    hdr.label_exp_s_ttl = clib_host_to_net_u32(hdr.label_exp_s_ttl);

                    fw_lbi = mpls_fib_table_forwarding_lookup(fib_index, &hdr);
                    break;
                }
            default:
                fw_lbi = 0;
            }
            FIB_TEST_LB((fw_lbi == dpo.dpoi_index),
                        "Contributed LB = FW LB:\n fwd:%U\n cont:%U",
                        format_load_balance, fw_lbi, 0,
                        format_load_balance, dpo.dpoi_index, 0);
        }
    }

    dpo_reset(&dpo);

    return (res);
}

static int
fib_test_v4 (void)
{
    /*
     * In the default table check for the presence and correct forwarding
     * of the special entries
     */
    fib_node_index_t dfrt, fei, ai, ai2, locked_ai, ai_01, ai_02, ai_03;
    const dpo_id_t *dpo, *dpo1, *dpo2, *dpo_drop;
    const ip_adjacency_t *adj;
    const load_balance_t *lb;
    test_main_t *tm;
    u32 fib_index;
    int lb_count;
    int ii, res;

    res = 0;
    /* via 10.10.10.1 */
    ip46_address_t nh_10_10_10_1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
    };
    /* via 10.10.10.2 */
    ip46_address_t nh_10_10_10_2 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
    };

    FIB_TEST((0 == pool_elts(load_balance_map_pool)), "LB-map pool size is %d",
             pool_elts(load_balance_map_pool));

    tm = &test_main;

    /* record the nubmer of load-balances in use before we start */
    lb_count = pool_elts(load_balance_pool);

    /* Find or create FIB table 11 */
    fib_index = fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4, 11,
                                                  FIB_SOURCE_API);

    for (ii = 0; ii < 4; ii++)
    {
        ip4_main.fib_index_by_sw_if_index[tm->hw[ii]->sw_if_index] = fib_index;
    }

    fib_prefix_t pfx_0_0_0_0_s_0 = {
        .fp_len = 0,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                {0}
            },
        },
    };

    fib_prefix_t pfx = {
        .fp_len = 0,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                {0}
            },
        },
    };

    dpo_drop = drop_dpo_get(DPO_PROTO_IP4);

    dfrt = fib_table_lookup(fib_index, &pfx_0_0_0_0_s_0);
    FIB_TEST((FIB_NODE_INDEX_INVALID != dfrt), "default route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(dfrt)),
             "Default route is DROP");

    pfx.fp_len = 32;
    fei = fib_table_lookup(fib_index, &pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "all zeros route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "all 0s route is DROP");

    pfx.fp_addr.ip4.as_u32 = clib_host_to_net_u32(0xffffffff);
    pfx.fp_len = 32;
    fei = fib_table_lookup(fib_index, &pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "all ones route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "all 1s route is DROP");

    pfx.fp_addr.ip4.as_u32 = clib_host_to_net_u32(0xe0000000);
    pfx.fp_len = 8;
    fei = fib_table_lookup(fib_index, &pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "all-mcast route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "all-mcast route is DROP");

    pfx.fp_addr.ip4.as_u32 = clib_host_to_net_u32(0xf0000000);
    pfx.fp_len = 8;
    fei = fib_table_lookup(fib_index, &pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "class-e route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "class-e route is DROP");

    /*
     * at this stage there are 5 entries in the test FIB (plus 5 in the default),
     * all of which are special sourced and so none of which share path-lists.
     * There are also 2 entries, and 2 non-shared path-lists, in the v6 default
     * table, and 4 path-lists in the v6 MFIB table and 2 in v4.
     */
#define ENBR (5+5+2)

    u32 PNBR = 5+5+2+4+2;

    /*
     * if the IGMP plugin is loaded this adds two more entries to the v4 MFIB
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * add interface routes.
     *  validate presence of /24 attached and /32 recieve.
     *  test for the presence of the receive address in the glean and local adj
     */
    fib_prefix_t local_pfx = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                .as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
            },
        },
    };

    fib_table_entry_update_one_path(fib_index, &local_pfx,
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
    fei = fib_table_lookup(fib_index, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached interface route present");
    FIB_TEST(((FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED) ==
              fib_entry_get_flags(fei)),
             "Flags set on attached interface");

    ai = fib_entry_get_adj(fei);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai),
             "attached interface route adj present %d", ai);
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index),
             "attached interface adj is glean");

    local_pfx.fp_len = 32;
    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1, // weight
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &local_pfx);
    FIB_TEST(((FIB_ENTRY_FLAG_LOCAL | FIB_ENTRY_FLAG_CONNECTED) ==
              fib_entry_get_flags(fei)),
             "Flags set on local interface");

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local interface route present");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 0),
             "RPF list for local length 0");
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST((DPO_RECEIVE == dpo->dpoi_type),
             "local interface adj is local");
    receive_dpo_t *rd = receive_dpo_get(dpo->dpoi_index);

    FIB_TEST((0 == ip46_address_cmp(&local_pfx.fp_addr,
                                    &rd->rd_addr)),
             "local interface adj is receive ok");

    FIB_TEST((2 == fib_table_get_num_entries(fib_index,
                                             FIB_PROTOCOL_IP4,
                                             FIB_SOURCE_INTERFACE)),
             "2 Interface Source'd prefixes");
    FIB_TEST((0 == ip46_address_cmp(&local_pfx.fp_addr,
                                    &adj->sub_type.glean.rx_pfx.fp_addr)),
             "attached interface adj is receive ok");

    /*
     * +2 interface routes +2 non-shared path-lists
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+2 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Modify the default route to be via an adj not yet known.
     * this sources the defalut route with the API source, which is
     * a higher preference to the DEFAULT_ROUTE source
     */
    pfx.fp_addr.ip4.as_u32 = 0;
    pfx.fp_len = 0;
    fib_table_entry_path_add(fib_index, &pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx);
    FIB_TEST((FIB_ENTRY_FLAG_NONE == fib_entry_get_flags(fei)),
             "Flags set on API route");

    FIB_TEST((fei == dfrt), "default route same index");
    ai = fib_entry_get_adj(fei);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai), "default route adj present");
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&nh_10_10_10_1, &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");
    FIB_TEST((1 == fib_table_get_num_entries(fib_index,
                                             FIB_PROTOCOL_IP4,
                                             FIB_SOURCE_API)),
             "1 API Source'd prefixes");

    /*
     * find the adj in the shared db
     */
    locked_ai = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                    VNET_LINK_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index);
    FIB_TEST((locked_ai == ai), "ADJ NBR DB find");
    adj_unlock(locked_ai);

    /*
     * +1 shared path-list
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+3 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * remove the API source from the default route. We expected
     * the route to remain, sourced by DEFAULT_ROUTE, and hence a DROP
     */
    pfx.fp_addr.ip4.as_u32 = 0;
    pfx.fp_len = 0;
    fib_table_entry_path_remove(fib_index, &pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0, // non-recursive path, so no FIB index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx);

    FIB_TEST((fei == dfrt), "default route same index");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "Default route is DROP");

    /*
     * -1 shared-path-list
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+2 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add an 2 ARP entry => a complete ADJ plus adj-fib.
     */
    fib_prefix_t pfx_10_10_10_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.1 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
        },
    };
    fib_prefix_t pfx_10_10_10_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.2 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
        },
    };
    fib_prefix_t pfx_11_11_11_11_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 11.11.11.11 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0b0b0b0b),
        },
    };
    u8 eth_addr[] = {
        0xde, 0xde, 0xde, 0xba, 0xba, 0xba,
    };

    ip46_address_t nh_12_12_12_12 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0c0c0c0c),
    };
    adj_index_t ai_12_12_12_12;

    /*
     * Add a route via an incomplete ADJ. then complete the ADJ
     * Expect the route LB is updated to use complete adj type.
     */
    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_11_11_11_11_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_ATTACHED,
                                          DPO_PROTO_IP4,
                                          &pfx_10_10_10_1_s_32.fp_addr,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          NULL,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo1 = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST(DPO_ADJACENCY_INCOMPLETE == dpo1->dpoi_type,
             "11.11.11.11/32 via incomplete adj");

    ai_01 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                VNET_LINK_IP4,
                                &pfx_10_10_10_1_s_32.fp_addr,
                                tm->hw[0]->sw_if_index);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai_01), "adj created");
    adj = adj_get(ai_01);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_10_10_10_1_s_32.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    adj_nbr_update_rewrite(ai_01, ADJ_NBR_REWRITE_FLAG_COMPLETE,
                           fib_test_build_rewrite(eth_addr));
    FIB_TEST((IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index),
             "adj is complete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_10_10_10_1_s_32.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "ADJ-FIB resolves via adj");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo1 = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST(DPO_ADJACENCY == dpo1->dpoi_type,
             "11.11.11.11/32 via complete adj");
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 1,
                                    tm->hw[0]->sw_if_index),
             "RPF list for adj-fib contains adj");

    ai_12_12_12_12 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                         VNET_LINK_IP4,
                                         &nh_12_12_12_12,
                                         tm->hw[1]->sw_if_index);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai_12_12_12_12), "adj created");
    adj = adj_get(ai_12_12_12_12);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&nh_12_12_12_12,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");
    adj_nbr_update_rewrite(ai_12_12_12_12, ADJ_NBR_REWRITE_FLAG_COMPLETE,
                           fib_test_build_rewrite(eth_addr));
    FIB_TEST((IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index),
             "adj is complete");

    /*
     * add the adj fib
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_10_10_10_1_s_32,
                                   FIB_SOURCE_ADJ,
                                   FIB_ENTRY_FLAG_ATTACHED,
                                   DPO_PROTO_IP4,
                                   &pfx_10_10_10_1_s_32.fp_addr,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST((FIB_ENTRY_FLAG_ATTACHED  == fib_entry_get_flags(fei)),
             "Flags set on adj-fib");
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "ADJ-FIB resolves via adj, %d", ai);

    fib_table_entry_path_remove(fib_index,
                                &pfx_11_11_11_11_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_10_10_10_1_s_32.fp_addr,
                                tm->hw[0]->sw_if_index,
                                ~0, // invalid fib index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    eth_addr[5] = 0xb2;

    ai_02 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                VNET_LINK_IP4,
                                &pfx_10_10_10_2_s_32.fp_addr,
                                tm->hw[0]->sw_if_index);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai_02), "adj created");
    adj = adj_get(ai_02);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_10_10_10_2_s_32.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    adj_nbr_update_rewrite(ai_02, ADJ_NBR_REWRITE_FLAG_COMPLETE,
                           fib_test_build_rewrite(eth_addr));
    FIB_TEST((IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index),
             "adj is complete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_10_10_10_2_s_32.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");
    FIB_TEST((ai_01 != ai_02), "ADJs are different");

    fib_table_entry_path_add(fib_index,
                             &pfx_10_10_10_2_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_10_10_10_2_s_32.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_10_10_10_2_s_32);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_02 == ai), "ADJ-FIB resolves via adj");

    /*
     * +2 adj-fibs, and their non-shared path-lists
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+4 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+4 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add 2 routes via the first ADJ. ensure path-list sharing
     */
    fib_prefix_t pfx_1_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 1.1.1.1/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x01010101),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.1.1 resolves via 10.10.10.1");

    /*
     * +1 entry and a shared path-list
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+5 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /* 1.1.2.0/24 */
    fib_prefix_t pfx_1_1_2_0_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010200),
        }
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_2_0_s_24,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_2_0_s_24);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.2.0/24 resolves via 10.10.10.1");

    /*
     * +1 entry only
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+6 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * modify 1.1.2.0/24 to use multipath.
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_2_0_s_24,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_2_0_s_24);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    1, tm->hw[0]->sw_if_index),
             "RPF list for 1.1.2.0/24 contains both adjs");

    dpo1 = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST(DPO_ADJACENCY == dpo1->dpoi_type, "type is %d", dpo1->dpoi_type);
    FIB_TEST((ai_01 == dpo1->dpoi_index),
             "1.1.2.0/24 bucket 0 resolves via 10.10.10.1 (%d=%d)",
             ai_01, dpo1->dpoi_index);

    dpo1 = load_balance_get_bucket(dpo->dpoi_index, 1);
    FIB_TEST(DPO_ADJACENCY == dpo1->dpoi_type, "type is %d", dpo1->dpoi_type);
    FIB_TEST((ai_02 == dpo1->dpoi_index),
             "1.1.2.0/24 bucket 1 resolves via 10.10.10.2");

    /*
     * +1 shared-pathlist
     */
    FIB_TEST((2 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNBR+6 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+6 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * revert the modify
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_2_0_s_24,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_2,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_2_0_s_24);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    1, tm->hw[0]->sw_if_index),
             "RPF list for 1.1.2.0/24 contains one adj");

    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.2.0/24 resolves via 10.10.10.1");

    /*
     * +1 shared-pathlist
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB is %d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+6 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add 2 recursive routes:
     *   100.100.100.100/32 via 1.1.1.1/32  => the via entry is installed.
     *   100.100.100.101/32 via 1.1.1.1/32  => the via entry is installed.
     */
    fib_prefix_t bgp_100_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 100.100.100.100/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x64646464),
        },
    };
    /* via 1.1.1.1 */
    ip46_address_t nh_1_1_1_1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x01010101),
    };

    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_100_pfx,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_1_1_1_1,
                                   ~0, // no index provided.
                                   fib_index, // nexthop in same fib as route
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST_REC_FORW(&bgp_100_pfx, &pfx_1_1_1_1_s_32, 0);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 1,
                                    tm->hw[0]->sw_if_index),
             "RPF list for adj-fib contains adj");

    /*
     * +1 entry and +1 shared-path-list
     */
    FIB_TEST((2  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+6 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    fib_prefix_t bgp_101_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 100.100.100.101/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x64646465),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &bgp_101_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_1_1_1_1,
                             ~0, // no index provided.
                             fib_index, // nexthop in same fib as route
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST_REC_FORW(&bgp_101_pfx, &pfx_1_1_1_1_s_32, 0);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 1,
                                    tm->hw[0]->sw_if_index),
             "RPF list for adj-fib contains adj");

    /*
     * +1 entry, but the recursive path-list is shared.
     */
    FIB_TEST((2  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+6 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+8 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * An special route; one where the user (me) provides the
     * adjacency through which the route will resovle by setting the flags
     */
    fib_prefix_t ex_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 4.4.4.4/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x04040404),
        },
    };

    fib_table_entry_special_add(fib_index,
                                &ex_pfx,
                                FIB_SOURCE_SPECIAL,
                                FIB_ENTRY_FLAG_LOCAL);
    fei = fib_table_lookup_exact_match(fib_index, &ex_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST((DPO_RECEIVE == dpo->dpoi_type),
             "local interface adj is local");

    fib_table_entry_special_remove(fib_index,
                                   &ex_pfx,
                                   FIB_SOURCE_SPECIAL);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &ex_pfx),
             "Exclusive reoute removed");

    /*
     * An EXCLUSIVE route; one where the user (me) provides the exclusive
     * adjacency through which the route will resovle
     */
    dpo_id_t ex_dpo = DPO_INVALID;

    lookup_dpo_add_or_lock_w_fib_index(fib_index,
                                       DPO_PROTO_IP4,
                                       LOOKUP_UNICAST,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_CONFIG,
                                       &ex_dpo);

    fib_table_entry_special_dpo_add(fib_index,
                                    &ex_pfx,
                                    FIB_SOURCE_SPECIAL,
                                    FIB_ENTRY_FLAG_EXCLUSIVE,
                                    &ex_dpo);
    fei = fib_table_lookup_exact_match(fib_index, &ex_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(&ex_dpo, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "exclusive remote uses lookup DPO");

    /*
     * update the exclusive to use a different DPO
     */
    ip_null_dpo_add_and_lock(DPO_PROTO_IP4,
                             IP_NULL_ACTION_SEND_ICMP_UNREACH,
                             &ex_dpo);
    fib_table_entry_special_dpo_update(fib_index,
                                       &ex_pfx,
                                       FIB_SOURCE_SPECIAL,
                                       FIB_ENTRY_FLAG_EXCLUSIVE,
                                       &ex_dpo);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(&ex_dpo, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "exclusive remote uses now uses NULL DPO");

    fib_table_entry_special_remove(fib_index,
                                   &ex_pfx,
                                   FIB_SOURCE_SPECIAL);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &ex_pfx),
             "Exclusive reoute removed");
    dpo_reset(&ex_dpo);

    /*
     * Add a recursive route:
     *   200.200.200.200/32 via 1.1.1.2/32  => the via entry is NOT installed.
     */
    fib_prefix_t bgp_200_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 200.200.200.200/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0xc8c8c8c8),
        },
    };
    /* via 1.1.1.2 */
    fib_prefix_t pfx_1_1_1_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010102),
        },
    };

    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_200_pfx,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_1_1_2_s_32.fp_addr,
                                   ~0, // no index provided.
                                   fib_index, // nexthop in same fib as route
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "Recursive via unresolved is drop");

    /*
     * the adj should be recursive via drop, since the route resolves via
     * the default route, which is itself a DROP
     */
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_2_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(load_balance_is_drop(dpo1), "1.1.1.2/32 is drop");
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 0),
             "RPF list for 1.1.1.2/32 contains 0 adjs");

    /*
     * +2 entry and +1 shared-path-list
     */
    FIB_TEST((3  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+7 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+10 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Unequal Cost load-balance. 3:1 ratio. fits in a 4 bucket LB
     * The paths are sort by NH first. in this case the the path with greater
     * weight is first in the set. This ordering is to test the RPF sort|uniq logic
     */
    fib_prefix_t pfx_1_2_3_4_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01020304),
        },
    };
    fib_table_entry_path_add(fib_index,
                             &pfx_1_2_3_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_1_2_3_4_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_12_12_12_12,
                                   tm->hw[1]->sw_if_index,
                                   ~0,
                                   3,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "1.2.3.4/32 presnet");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    lb = load_balance_get(dpo->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 4),
             "1.2.3.4/32 LB has %d bucket",
             lb->lb_n_buckets);

    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_4_s_32, 0, ai_12_12_12_12);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_4_s_32, 1, ai_12_12_12_12);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_4_s_32, 2, ai_12_12_12_12);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_4_s_32, 3, ai_01);

    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 2,
                                    tm->hw[0]->sw_if_index,
                                    tm->hw[1]->sw_if_index),
             "RPF list for 1.2.3.4/32 contains both adjs");


    /*
     * Unequal Cost load-balance. 4:1 ratio.
     *  fits in a 16 bucket LB with ratio 13:3
     */
    fib_prefix_t pfx_1_2_3_5_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01020305),
        },
    };
    fib_table_entry_path_add(fib_index,
                             &pfx_1_2_3_5_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_12_12_12_12,
                             tm->hw[1]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_1_2_3_5_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   ~0,
                                   4,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "1.2.3.5/32 presnet");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    lb = load_balance_get(dpo->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 16),
             "1.2.3.5/32 LB has %d bucket",
             lb->lb_n_buckets);

    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 0, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 1, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 2, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 3, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 4, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 5, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 6, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 7, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 8, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 9, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 10, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 11, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 12, ai_01);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 13, ai_12_12_12_12);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 14, ai_12_12_12_12);
    FIB_TEST_LB_BUCKET_VIA_ADJ(&pfx_1_2_3_5_s_32, 15, ai_12_12_12_12);

    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 2,
                                    tm->hw[0]->sw_if_index,
                                    tm->hw[1]->sw_if_index),
             "RPF list for 1.2.3.4/32 contains both adjs");

    /*
     * Test UCMP with a large weight skew - this produces load-balance objects with large
     * numbers of buckets to accommodate the skew. By updating said load-balances we are
     * laso testing the LB in placce modify code when number of buckets is large.
     */
    fib_prefix_t pfx_6_6_6_6_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 1.1.1.1/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x06060606),
        },
    };
    fib_test_lb_bucket_t ip_o_10_10_10_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_01,
        },
    };
    fib_test_lb_bucket_t ip_o_10_10_10_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_02,
        },
    };
    fib_test_lb_bucket_t ip_6_6_6_6_o_12_12_12_12 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_12_12_12_12,
        },
    };
    fib_table_entry_update_one_path(fib_index,
                                    &pfx_6_6_6_6_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    0,  // zero weigth
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_6_6_6_6_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_10_10_10_1),
             "6.6.6.6/32 via 10.10.10.1");

    fib_table_entry_path_add(fib_index,
                             &pfx_6_6_6_6_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             100,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_6_6_6_6_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      64,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_1),
             "6.6.6.6/32 via 10.10.10.1 and 10.10.10.2 in 63:1 ratio");

    fib_table_entry_path_add(fib_index,
                             &pfx_6_6_6_6_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_12_12_12_12,
                             tm->hw[1]->sw_if_index,
                             ~0, // invalid fib index
                             100,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_6_6_6_6_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      128,
                                      &ip_o_10_10_10_1,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12,
                                      &ip_6_6_6_6_o_12_12_12_12),
             "6.6.6.6/32 via 10.10.10.1 and 10.10.10.2 in 63:1 ratio");

    fib_table_entry_path_remove(fib_index,
                                &pfx_6_6_6_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_12_12_12_12,
                                tm->hw[1]->sw_if_index,
                                ~0, // invalid fib index
                                100,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_6_6_6_6_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      64,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_2,
                                      &ip_o_10_10_10_1),
             "6.6.6.6/32 via 10.10.10.1 and 10.10.10.2 in 63:1 ratio");

    fib_table_entry_path_remove(fib_index,
                                &pfx_6_6_6_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_2,
                                tm->hw[0]->sw_if_index,
                                ~0, // invalid fib index
                                100,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_6_6_6_6_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_10_10_10_1),
             "6.6.6.6/32 via 10.10.10.1");

    fib_table_entry_delete(fib_index, &pfx_6_6_6_6_s_32, FIB_SOURCE_API);

    /*
     * A recursive via the two unequal cost entries
     */
    fib_prefix_t bgp_44_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 200.200.200.201/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x44444444),
        },
    };
    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_44_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_2_3_4_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_44_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_2_3_5_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST_REC_FORW(&bgp_44_s_32, &pfx_1_2_3_4_s_32, 0);
    FIB_TEST_REC_FORW(&bgp_44_s_32, &pfx_1_2_3_5_s_32, 1);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 2,
                                    tm->hw[0]->sw_if_index,
                                    tm->hw[1]->sw_if_index),
             "RPF list for 1.2.3.4/32 contains both adjs");

    /*
     * test the uRPF check functions
     */
    dpo_id_t dpo_44 = DPO_INVALID;
    index_t urpfi;

    fib_entry_contribute_forwarding(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, &dpo_44);
    urpfi = load_balance_get_urpf(dpo_44.dpoi_index);

    FIB_TEST(fib_urpf_check(urpfi, tm->hw[0]->sw_if_index),
             "uRPF check for 68.68.68.68/32 on %d OK",
             tm->hw[0]->sw_if_index);
    FIB_TEST(fib_urpf_check(urpfi, tm->hw[1]->sw_if_index),
             "uRPF check for 68.68.68.68/32 on %d OK",
             tm->hw[1]->sw_if_index);
    FIB_TEST(!fib_urpf_check(urpfi, 99),
             "uRPF check for 68.68.68.68/32 on 99 not-OK",
             99);
    dpo_reset(&dpo_44);

    fib_table_entry_delete(fib_index,
                           &bgp_44_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_1_2_3_5_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_1_2_3_4_s_32,
                           FIB_SOURCE_API);

    /*
     * Add a recursive route:
     *   200.200.200.201/32 via 1.1.1.200/32  => the via entry is NOT installed.
     */
    fib_prefix_t bgp_201_pfx = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 200.200.200.201/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0xc8c8c8c9),
        },
    };
    /* via 1.1.1.200 */
    fib_prefix_t pfx_1_1_1_200_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x010101c8),
        },
    };

    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_201_pfx,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_1_1_200_s_32.fp_addr,
                                   ~0, // no index provided.
                                   fib_index, // nexthop in same fib as route
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "Recursive via unresolved is drop");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_200_s_32);
    FIB_TEST((FIB_ENTRY_FLAG_NONE == fib_entry_get_flags(fei)),
             "Flags set on RR via non-attached");
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 0),
             "RPF list for BGP route empty");

    /*
     * +2 entry (BGP & RR) and +1 shared-path-list
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+12 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * insert a route that covers the missing 1.1.1.2/32. we epxect
     * 200.200.200.200/32 and 200.200.200.201/32 to resolve through it.
     */
    fib_prefix_t pfx_1_1_1_0_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 1.1.1.0/24 */
            .ip4.as_u32 = clib_host_to_net_u32(0x01010100),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_0_s_24,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_0_s_24);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.1.0/24 resolves via 10.10.10.1");
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_2_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.1.2/32 resolves via 10.10.10.1");
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_200_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "1.1.1.200/24 resolves via 10.10.10.1");

    /*
     * +1 entry. 1.1.1.1/32 already uses 10.10.10.1 so no new pah-list
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+13 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * the recursive adj for 200.200.200.200 should be updated.
     */
    FIB_TEST_REC_FORW(&bgp_201_pfx, &pfx_1_1_1_200_s_32, 0);
    FIB_TEST_REC_FORW(&bgp_200_pfx, &pfx_1_1_1_2_s_32, 0);
    fei = fib_table_lookup(fib_index, &bgp_200_pfx);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 1,
                                    tm->hw[0]->sw_if_index),
             "RPF list for BGP route has itf index 0");

    /*
     * insert a more specific route than 1.1.1.0/24 that also covers the
     * missing 1.1.1.2/32, but not 1.1.1.200/32. we expect
     * 200.200.200.200 to resolve through it.
     */
    fib_prefix_t pfx_1_1_1_0_s_28 = {
        .fp_len = 28,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 1.1.1.0/24 */
            .ip4.as_u32 = clib_host_to_net_u32(0x01010100),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_0_s_28,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_1_1_1_0_s_28);
    dpo2 = fib_entry_contribute_ip_forwarding(fei);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_02 == ai), "1.1.1.0/24 resolves via 10.10.10.2");

    /*
     * +1 entry. +1 shared path-list
     */
    FIB_TEST((5  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+9 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+14 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * the recursive adj for 200.200.200.200 should be updated.
     * 200.200.200.201 remains unchanged.
     */
    FIB_TEST_REC_FORW(&bgp_201_pfx, &pfx_1_1_1_200_s_32, 0);
    FIB_TEST_REC_FORW(&bgp_200_pfx, &pfx_1_1_1_2_s_32, 0);

    /*
     * remove this /28. 200.200.200.200/32 should revert back to via 1.1.1.0/24
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_0_s_28,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_2,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_0_s_28) ==
              FIB_NODE_INDEX_INVALID),
             "1.1.1.0/28 removed");
    FIB_TEST((fib_table_lookup(fib_index, &pfx_1_1_1_0_s_28) ==
              fib_table_lookup(fib_index, &pfx_1_1_1_0_s_24)),
             "1.1.1.0/28 lookup via /24");
    FIB_TEST_REC_FORW(&bgp_201_pfx, &pfx_1_1_1_200_s_32, 0);
    FIB_TEST_REC_FORW(&bgp_200_pfx, &pfx_1_1_1_2_s_32, 0);

    /*
     * -1 entry. -1 shared path-list
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+13 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * remove 1.1.1.0/24. 200.200.200.200/32 should revert back to via 0.0.0.0/0
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_0_s_24,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_0_s_24) ==
              FIB_NODE_INDEX_INVALID),
             "1.1.1.0/24 removed");

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_2_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "1.1.1.2/32 route is DROP");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_200_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "1.1.1.200/32 route is DROP");

    fei = fib_table_lookup_exact_match(fib_index, &bgp_201_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "201 is drop");
    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "200 is drop");

    /*
     * -1 entry
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+12 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * insert the missing 1.1.1.2/32
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_1_1_1_2_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai = ai_01), "1.1.1.2/32 resolves via 10.10.10.1");

    fei = fib_table_lookup_exact_match(fib_index, &bgp_201_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "201 is drop");
    FIB_TEST_REC_FORW(&bgp_200_pfx, &pfx_1_1_1_2_s_32, 0);

    /*
     * no change. 1.1.1.2/32 was already there RR sourced.
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+12 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * give 201 a resolved path.
     *  it now has the unresolved 1.1.1.200 and the resolved 1.1.1.2,
     *  only the latter contributes forwarding.
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &bgp_201_pfx,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_1_1_2_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST_REC_FORW(&bgp_201_pfx, &pfx_1_1_1_2_s_32, 0);
    fib_table_entry_path_remove(fib_index,
                                &bgp_201_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_2_s_32.fp_addr,
                                ~0,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * remove 200.200.200.201/32 which does not have a valid via FIB
     */
    fib_table_entry_path_remove(fib_index,
                                &bgp_201_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_200_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * -2 entries (BGP and RR). -1 shared path-list;
     */
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_201_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "200.200.200.201/32 removed");
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_200_s_32) ==
              FIB_NODE_INDEX_INVALID),
             "1.1.1.200/32 removed");

    FIB_TEST((3  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+7 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+10 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * remove 200.200.200.200/32 which does have a valid via FIB
     */
    fib_table_entry_path_remove(fib_index,
                                &bgp_200_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_2_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_200_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "200.200.200.200/32 removed");
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_2_s_32) !=
              FIB_NODE_INDEX_INVALID),
             "1.1.1.2/32 still present");

    /*
     * -1 entry (BGP, the RR source is also API sourced). -1 shared path-list;
     */
    FIB_TEST((2  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+6 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+9 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * A recursive prefix that has a 2 path  load-balance.
     * It also shares a next-hop with other BGP prefixes and hence
     * test the ref counting of RR sourced prefixes and 2 level LB.
     */
    const fib_prefix_t bgp_102 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 100.100.100.101/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x64646466),
        },
    };
    fib_table_entry_path_add(fib_index,
                             &bgp_102,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_1_1_1_1_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index, // same as route
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_add(fib_index,
                             &bgp_102,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_1_1_1_2_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index, // same as route's FIB
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &bgp_102);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "100.100.100.102/32 presnet");
    dpo = fib_entry_contribute_ip_forwarding(fei);

    fei  = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_1_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    fei  = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_2_s_32);
    dpo2 = fib_entry_contribute_ip_forwarding(fei);

    lb = load_balance_get(dpo->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 2), "Recursive LB has %d bucket", lb->lb_n_buckets);
    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "First via 10.10.10.1");
    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket(dpo->dpoi_index, 1)),
             "Second via 10.10.10.1");

    fib_table_entry_path_remove(fib_index,
                                &bgp_102,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_1_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &bgp_102,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_2_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &bgp_102);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "100.100.100.102/32 removed");

    /*
     * remove the remaining recursives
     */
    fib_table_entry_path_remove(fib_index,
                                &bgp_100_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_1_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &bgp_101_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_1_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_100_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "100.100.100.100/32 removed");
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_101_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "100.100.100.101/32 removed");

    /*
     * -2 entry (2*BGP, the RR source is also API sourced). -1 shared path-list;
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add a recursive route via a connected cover, using an adj-fib that does exist
     */
    fib_table_entry_path_add(fib_index,
                             &bgp_200_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             ~0, // no index provided.
                             fib_index, // Same as route's FIB
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * +1 entry. +1 shared path-list (recursive via 10.10.10.1)
     */
    FIB_TEST((2  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+6 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+8 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);

    fei  = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);

    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "200.200.200.200/32 is recursive via adj for 10.10.10.1");

    FIB_TEST((FIB_ENTRY_FLAG_ATTACHED  == fib_entry_get_flags(fei)),
             "Flags set on RR via existing attached");

    /*
     * Add a recursive route via a connected cover, using and adj-fib that does
     * not exist
     */
    ip46_address_t nh_10_10_10_3 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a03),
    };
    fib_prefix_t pfx_10_10_10_3 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_3,
    };

    fib_table_entry_path_add(fib_index,
                             &bgp_201_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_3,
                             ~0, // no index provided.
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * +2 entries (BGP and RR). +1 shared path-list (recursive via 10.10.10.3) and
     * one unshared non-recursive via 10.10.10.3
     */
    FIB_TEST((3  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+10 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    ai_03 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                VNET_LINK_IP4,
                                &nh_10_10_10_3,
                                tm->hw[0]->sw_if_index);

    fei  = fib_table_lookup_exact_match(fib_index, &bgp_201_pfx);
    dpo  = fib_entry_contribute_ip_forwarding(fei);
    fei  = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_3);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);

    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai == ai_03), "adj for 10.10.10.3/32 is via adj for 10.10.10.3");
    FIB_TEST(((FIB_ENTRY_FLAG_ATTACHED | FIB_ENTRY_FLAG_CONNECTED) ==
              fib_entry_get_flags(fei)),
             "Flags set on RR via non-existing attached");

    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "adj for 200.200.200.200/32 is recursive via adj for 10.10.10.3");

    adj_unlock(ai_03);

    /*
     * remove the recursives
     */
    fib_table_entry_path_remove(fib_index,
                                &bgp_200_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &bgp_201_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_3,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_201_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "200.200.200.201/32 removed");
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &bgp_200_pfx) ==
              FIB_NODE_INDEX_INVALID),
             "200.200.200.200/32 removed");
    FIB_TEST((fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_3) ==
              FIB_NODE_INDEX_INVALID),
             "10.10.10.3/32 removed");

    /*
     * -3 entries (2*BGP and RR). -2 shared path-list (recursive via 10.10.10.3 &
     *  10.10.10.1) and one unshared non-recursive via 10.10.10.3
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());


    /*
     * RECURSION LOOPS
     *  Add 5.5.5.5/32 -> 5.5.5.6/32 -> 5.5.5.7/32 -> 5.5.5.5/32
     */
    fib_prefix_t pfx_5_5_5_5_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x05050505),
        },
    };
    fib_prefix_t pfx_5_5_5_6_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x05050506),
        },
    };
    fib_prefix_t pfx_5_5_5_7_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x05050507),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_5_5_5_5_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_5_5_5_6_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_add(fib_index,
                             &pfx_5_5_5_6_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_5_5_5_7_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_add(fib_index,
                             &pfx_5_5_5_7_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_5_5_5_5_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    /*
     * +3 entries, +3 shared path-list
     */
    FIB_TEST((4  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+8 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+10 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * All the entries have only looped paths, so they are all drop
     */
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_7_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.7/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_5_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.5/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_6_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.6/32 is via adj for DROP");

    /*
     * provide 5.5.5.6/32 with alternate path.
     * this will allow only 5.5.5.6/32 to forward with this path, the others
     * are still drop since the loop is still present.
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_5_5_5_6_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_5_5_5_6_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);

    lb = load_balance_get(dpo1->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 1), "5.5.5.6 LB has %d bucket", lb->lb_n_buckets);

    dpo2 = load_balance_get_bucket(dpo1->dpoi_index, 0);
    FIB_TEST(DPO_ADJACENCY == dpo2->dpoi_type, "type is %d", dpo2->dpoi_type);
    FIB_TEST((ai_01 == dpo2->dpoi_index),
             "5.5.5.6 bucket 0 resolves via 10.10.10.2");

    fei = fib_table_lookup(fib_index, &pfx_5_5_5_7_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.7/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_5_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.5/32 is via adj for DROP");

    /*
     * remove the alternate path for 5.5.5.6/32
     * back to all drop
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_5_5_5_7_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.7/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_5_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.5/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_6_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.6/32 is via adj for DROP");

    /*
     * break the loop by giving 5.5.5.5/32 a new set of paths
     * expect all to forward via this new path.
     */
    fib_table_entry_update_one_path(fib_index,
                                    &pfx_5_5_5_5_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_5_5_5_5_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    lb = load_balance_get(dpo1->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 1), "5.5.5.5 LB has %d bucket", lb->lb_n_buckets);

    dpo2 = load_balance_get_bucket(dpo1->dpoi_index, 0);
    FIB_TEST(DPO_ADJACENCY == dpo2->dpoi_type, "type is %d", dpo2->dpoi_type);
    FIB_TEST((ai_01 == dpo2->dpoi_index),
             "5.5.5.5 bucket 0 resolves via 10.10.10.2");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_5_5_5_7_s_32);
    dpo2 = fib_entry_contribute_ip_forwarding(fei);

    lb = load_balance_get(dpo2->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 1), "Recursive LB has %d bucket", lb->lb_n_buckets);
    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket(dpo2->dpoi_index, 0)),
             "5.5.5.5.7 via 5.5.5.5");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_5_5_5_6_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);

    lb = load_balance_get(dpo1->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 1), "Recursive LB has %d bucket", lb->lb_n_buckets);
    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket(dpo1->dpoi_index, 0)),
             "5.5.5.5.6 via 5.5.5.7");

    /*
     * revert back to the loop. so we can remove the prefixes with
     * the loop intact
     */
    fib_table_entry_update_one_path(fib_index,
                                    &pfx_5_5_5_5_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &pfx_5_5_5_6_s_32.fp_addr,
                                    ~0, // no index provided.
                                    fib_index,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_5_5_5_7_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.7/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_5_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.5/32 is via adj for DROP");
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_6_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "LB for 5.5.5.6/32 is via adj for DROP");

    /*
     * remove all the 5.5.5.x/32 prefixes
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_5_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_5_5_5_6_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_5_5_5_7_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_7_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_5_5_5_5_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_2,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * -3 entries, -3 shared path-list
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Single level loop 5.5.5.5/32 via 5.5.5.5/32
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_5_5_5_6_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_5_5_5_6_s_32.fp_addr,
                             ~0, // no index provided.
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_5_5_5_6_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "1-level 5.5.5.6/32 loop is via adj for DROP");

    fib_table_entry_path_remove(fib_index,
                                &pfx_5_5_5_6_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_5_5_5_6_s_32.fp_addr,
                                ~0, // no index provided.
                                fib_index, // same as route's FIB
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_5_5_5_6_s_32),
             "1-level 5.5.5.6/32 loop is removed");

    /*
     * A recursive route whose next-hop is covered by the prefix.
     * This would mean the via-fib, which inherits forwarding from its
     * cover, thus picks up forwarding from the prfix, which is via the
     * via-fib, and we have a loop.
     */
    fib_prefix_t pfx_23_23_23_0_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x17171700),
        },
    };
    fib_prefix_t pfx_23_23_23_23_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x17171717),
        },
    };
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_23_23_23_0_s_24,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_23_23_23_23_s_32.fp_addr,
                                   ~0, // recursive
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(load_balance_is_drop(dpo),
             "23.23.23.0/24 via covered is DROP");
    fib_table_entry_delete_index(fei, FIB_SOURCE_API);

    /*
     * add-remove test. no change.
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Make the default route recursive via a unknown next-hop. Thus the
     * next hop's cover would be the default route
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_0_0_0_0_s_0,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_23_23_23_23_s_32.fp_addr,
                                   ~0, // recursive
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(load_balance_is_drop(dpo),
             "0.0.0.0.0/0 via is DROP");
    FIB_TEST((fib_entry_get_resolving_interface(fei) == ~0),
             "no resolving interface for looped 0.0.0.0/0");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_23_23_23_23_s_32);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(load_balance_is_drop(dpo),
             "23.23.23.23/32 via is DROP");
    FIB_TEST((fib_entry_get_resolving_interface(fei) == ~0),
             "no resolving interface for looped 23.23.23.23/32");

    fib_table_entry_delete(fib_index, &pfx_0_0_0_0_s_0, FIB_SOURCE_API);

    /*
     * A recursive route with recursion constraints.
     *  200.200.200.200/32 via 1.1.1.1 is recurse via host constrained
     */
    fib_table_entry_path_add(fib_index,
                             &bgp_200_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_1_1_1_1,
                             ~0,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_RESOLVE_VIA_HOST);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_1_s_32);
    dpo2 = fib_entry_contribute_ip_forwarding(fei);

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);

    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket(dpo1->dpoi_index, 0)),
             "adj for 200.200.200.200/32 is recursive via adj for 1.1.1.1");

    /*
     * save the load-balance. we expect it to be inplace modified
     */
    lb = load_balance_get(dpo1->dpoi_index);

    /*
     * add a covering prefix for the via fib that would otherwise serve
     * as the resolving route when the host is removed
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_0_s_28,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_0_s_28);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai == ai_01),
             "adj for 1.1.1.0/28 is via adj for 1.1.1.1");

    /*
     * remove the host via FIB - expect the BGP prefix to be drop
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0, // invalid fib index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo1->dpoi_index, 0)),
             "adj for 200.200.200.200/32 is recursive via adj for DROP");

    /*
     * add the via-entry host reoute back. expect to resolve again
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket(dpo1->dpoi_index, 0)),
             "adj for 200.200.200.200/32 is recursive via adj for 1.1.1.1");

    /*
     * add another path for the recursive. it will then have 2.
     */
    fib_prefix_t pfx_1_1_1_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010103),
        },
    };
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_3_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fib_table_entry_path_add(fib_index,
                             &bgp_200_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_1_1_1_3_s_32.fp_addr,
                             ~0,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_RESOLVE_VIA_HOST);

    /*
     * add a bunch load more entries using this path combo so that we get
     * an LB-map created.
     */
#define N_P 128
    fib_prefix_t bgp_78s[N_P];
    for (ii = 0; ii < N_P; ii++)
    {
        bgp_78s[ii].fp_len = 32;
        bgp_78s[ii].fp_proto = FIB_PROTOCOL_IP4;
        bgp_78s[ii].fp_addr.ip4.as_u32 = clib_host_to_net_u32(0x4e000000+ii);


        fib_table_entry_path_add(fib_index,
                                 &bgp_78s[ii],
                                 FIB_SOURCE_API,
                                 FIB_ENTRY_FLAG_NONE,
                                 DPO_PROTO_IP4,
                                 &pfx_1_1_1_3_s_32.fp_addr,
                                 ~0,
                                 fib_index,
                                 1,
                                 NULL,
                                 FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
        fib_table_entry_path_add(fib_index,
                                 &bgp_78s[ii],
                                 FIB_SOURCE_API,
                                 FIB_ENTRY_FLAG_NONE,
                                 DPO_PROTO_IP4,
                                 &nh_1_1_1_1,
                                 ~0,
                                 fib_index,
                                 1,
                                 NULL,
                                 FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
    }

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_1_s_32);
    dpo2 = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "adj for 200.200.200.200/32 is recursive via adj for 1.1.1.1");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_3_s_32);
    dpo1 = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket(dpo->dpoi_index, 1)),
             "adj for 200.200.200.200/32 is recursive via adj for 1.1.1.3");

    /*
     * expect the lb-map used by the recursive's load-balance is using both buckets
     */
    load_balance_map_t *lbm;
    index_t lbmi;

    lb = load_balance_get(dpo->dpoi_index);
    lbmi = lb->lb_map;
    load_balance_map_lock(lbmi);
    lbm = load_balance_map_get(lbmi);

    FIB_TEST(lbm->lbm_buckets[0] == 0,
             "LB maps's bucket 0 is %d",
             lbm->lbm_buckets[0]);
    FIB_TEST(lbm->lbm_buckets[1] == 1,
             "LB maps's bucket 1 is %d",
             lbm->lbm_buckets[1]);

    /*
     * withdraw one of the /32 via-entrys.
     * that ECMP path will be unresolved and forwarding should continue on the
     * other available path. this is an iBGP PIC edge failover.
     * Test the forwarding changes without re-fetching the adj from the
     * recursive entry. this ensures its the same one that is updated; i.e. an
     * inplace-modify.
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0, // invalid fib index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    /* suspend so the update walk kicks int */
    vlib_process_suspend(vlib_get_main(), 1e-5);

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    FIB_TEST(!dpo_cmp(dpo, fib_entry_contribute_ip_forwarding(fei)),
             "post PIC 200.200.200.200/32 was inplace modified");

    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket_i(lb, 0)),
             "post PIC adj for 200.200.200.200/32 is recursive"
             " via adj for 1.1.1.3");

    /*
     * the LB maps that was locked above should have been modified to remove
     * the path that was down, and thus its bucket points to a path that is
     * still up.
     */
    FIB_TEST(lbm->lbm_buckets[0] == 1,
             "LB maps's bucket 0 is %d",
             lbm->lbm_buckets[0]);
    FIB_TEST(lbm->lbm_buckets[1] == 1,
             "LB maps's bucket 1 is %d",
             lbm->lbm_buckets[1]);

    load_balance_map_unlock(lbmi);

    /*
     * add it back. again
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    /* suspend so the update walk kicks in */
    vlib_process_suspend(vlib_get_main(), 1e-5);

    FIB_TEST(!dpo_cmp(dpo2, load_balance_get_bucket_i(lb, 0)),
             "post PIC recovery adj for 200.200.200.200/32 is recursive "
             "via adj for 1.1.1.1");
    FIB_TEST(!dpo_cmp(dpo1, load_balance_get_bucket_i(lb, 1)),
             "post PIC recovery adj for 200.200.200.200/32 is recursive "
             "via adj for 1.1.1.3");

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(lb == load_balance_get(dpo->dpoi_index),
             "post PIC 200.200.200.200/32 was inplace modified");

    /*
     * add a 3rd path. this makes the LB 16 buckets.
     */
    fib_table_entry_path_add(fib_index,
                             &bgp_200_pfx,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &pfx_1_1_1_2_s_32.fp_addr,
                             ~0,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
    for (ii = 0; ii < N_P; ii++)
    {
        fib_table_entry_path_add(fib_index,
                                 &bgp_78s[ii],
                                 FIB_SOURCE_API,
                                 FIB_ENTRY_FLAG_NONE,
                                 DPO_PROTO_IP4,
                                 &pfx_1_1_1_2_s_32.fp_addr,
                                 ~0,
                                 fib_index,
                                 1,
                                 NULL,
                                 FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
    }

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(lb == load_balance_get(dpo->dpoi_index),
             "200.200.200.200/32 was inplace modified for 3rd path");
    FIB_TEST(16 == lb->lb_n_buckets,
             "200.200.200.200/32 was inplace modified for 3rd path to 16 buckets");

    lbmi = lb->lb_map;
    load_balance_map_lock(lbmi);
    lbm = load_balance_map_get(lbmi);

    for (ii = 0; ii < 16; ii++)
    {
        FIB_TEST(lbm->lbm_buckets[ii] == ii,
                 "LB Map for 200.200.200.200/32 at %d is %d",
                 ii, lbm->lbm_buckets[ii]);
    }

    /*
     * trigger PIC by removing the first via-entry
     * the first 6 buckets of the map should map to the next 6
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    /* suspend so the update walk kicks int */
    vlib_process_suspend(vlib_get_main(), 1e-5);

    fei = fib_table_lookup_exact_match(fib_index, &bgp_200_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(lb == load_balance_get(dpo->dpoi_index),
             "200.200.200.200/32 was inplace modified for 3rd path");
    FIB_TEST(2 == lb->lb_n_buckets,
             "200.200.200.200/32 was inplace modified for 3rd path remove to 2 buckets");

    for (ii = 0; ii < 6; ii++)
    {
        FIB_TEST(lbm->lbm_buckets[ii] == ii+6,
                 "LB Map for 200.200.200.200/32 at %d is %d",
                 ii, lbm->lbm_buckets[ii]);
    }
    for (ii = 6; ii < 16; ii++)
    {
        FIB_TEST(lbm->lbm_buckets[ii] == ii,
                 "LB Map for 200.200.200.200/32 at %d is %d",
                 ii, lbm->lbm_buckets[ii]);
    }
    load_balance_map_unlock(lbmi);

    /*
     * tidy up
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    for (ii = 0; ii < N_P; ii++)
    {
        fib_table_entry_delete(fib_index,
                               &bgp_78s[ii],
                               FIB_SOURCE_API);
        FIB_TEST((FIB_NODE_INDEX_INVALID ==
                  fib_table_lookup_exact_match(fib_index, &bgp_78s[ii])),
                 "%U removed",
                 format_fib_prefix, &bgp_78s[ii]);
    }
    fib_table_entry_path_remove(fib_index,
                                &bgp_200_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_2_s_32.fp_addr,
                                ~0,
                                fib_index,
                                1,
                                MPLS_LABEL_INVALID);
    fib_table_entry_path_remove(fib_index,
                                &bgp_200_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_1_1_1_1,
                                ~0,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
    fib_table_entry_path_remove(fib_index,
                                &bgp_200_pfx,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &pfx_1_1_1_3_s_32.fp_addr,
                                ~0,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_RESOLVE_VIA_HOST);
    fib_table_entry_delete(fib_index,
                           &pfx_1_1_1_3_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_1_1_1_0_s_28,
                           FIB_SOURCE_API);
    /* suspend so the update walk kicks int */
    vlib_process_suspend(vlib_get_main(), 1e-5);
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_0_s_28)),
             "1.1.1.1/28 removed");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_3_s_32)),
             "1.1.1.3/32 removed");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &bgp_200_pfx)),
             "200.200.200.200/32 removed");

    /*
     * add-remove test. no change.
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * A route whose paths are built up iteratively and then removed
     * all at once
     */
    fib_prefix_t pfx_4_4_4_4_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 4.4.4.4/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x04040404),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_4_4_4_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_add(fib_index,
                             &pfx_4_4_4_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_add(fib_index,
                             &pfx_4_4_4_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_3,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(FIB_NODE_INDEX_INVALID !=
             fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32),
             "4.4.4.4/32 present");

    fib_table_entry_delete(fib_index,
                           &pfx_4_4_4_4_s_32,
                           FIB_SOURCE_API);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32),
             "4.4.4.4/32 removed");

    /*
     * add-remove test. no change.
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * A route with multiple paths at once
     */
    fib_route_path_t *r_paths = NULL;

    for (ii = 0; ii < 4; ii++)
    {
        fib_route_path_t r_path = {
            .frp_proto = DPO_PROTO_IP4,
            .frp_addr = {
                .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02 + ii),
            },
            .frp_sw_if_index = tm->hw[0]->sw_if_index,
            .frp_weight = 1,
            .frp_fib_index = ~0,
        };
        vec_add1(r_paths, r_path);
    }

    fib_table_entry_update(fib_index,
                           &pfx_4_4_4_4_s_32,
                           FIB_SOURCE_API,
                           FIB_ENTRY_FLAG_NONE,
                           r_paths);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "4.4.4.4/32 present");
    dpo = fib_entry_contribute_ip_forwarding(fei);

    lb = load_balance_get(dpo->dpoi_index);
    FIB_TEST((lb->lb_n_buckets == 4), "4.4.4.4/32 lb over %d paths", lb->lb_n_buckets);

    fib_table_entry_delete(fib_index,
                           &pfx_4_4_4_4_s_32,
                           FIB_SOURCE_API);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32),
             "4.4.4.4/32 removed");
    vec_free(r_paths);

    /*
     * add-remove test. no change.
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * A route deag route
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_4_4_4_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &zero_addr,
                             ~0,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "4.4.4.4/32 present");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    lookup_dpo_t *lkd = lookup_dpo_get(dpo->dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
             "4.4.4.4/32 is deag in %d %U",
             lkd->lkd_fib_index,
             format_dpo_id, dpo, 0);
    FIB_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
             "4.4.4.4/32 is source deag in %d %U",
             lkd->lkd_input,
             format_dpo_id, dpo, 0);

    fib_table_entry_delete(fib_index,
                           &pfx_4_4_4_4_s_32,
                           FIB_SOURCE_API);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32),
             "4.4.4.4/32 removed");
    vec_free(r_paths);

    /*
     * A route deag route in a source lookup table
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_4_4_4_4_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &zero_addr,
                             ~0,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_SOURCE_LOOKUP);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "4.4.4.4/32 present");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    lkd = lookup_dpo_get(dpo->dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
             "4.4.4.4/32 is deag in %d %U",
             lkd->lkd_fib_index,
             format_dpo_id, dpo, 0);
    FIB_TEST((LOOKUP_INPUT_SRC_ADDR == lkd->lkd_input),
             "4.4.4.4/32 is source deag in %d %U",
             lkd->lkd_input,
             format_dpo_id, dpo, 0);

    fib_table_entry_delete(fib_index,
                           &pfx_4_4_4_4_s_32,
                           FIB_SOURCE_API);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_4_4_4_4_s_32),
             "4.4.4.4/32 removed");
    vec_free(r_paths);

    /*
     * add-remove test. no change.
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+7 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Duplicate paths:
     *  add a recursive with duplicate paths. Expect the duplicate to be ignored.
     */
    fib_prefix_t pfx_34_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x22010101),
        },
    };
    fib_prefix_t pfx_34_34_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x22220101),
        },
    };
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_34_34_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   0,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_34_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_34_34_1_1_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_34_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_34_34_1_1_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST_REC_FORW(&pfx_34_1_1_1_s_32, &pfx_34_34_1_1_s_32, 0);
    fib_table_entry_delete_index(fei, FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_34_34_1_1_s_32,
                           FIB_SOURCE_API);

    /*
     * CLEANUP
     *   remove: 1.1.1.2/32, 1.1.2.0/24 and 1.1.1.1/32
     *           all of which are via 10.10.10.1, Itf1
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_2_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_2_0_s_24,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_1_s_32),
             "1.1.1.1/32 removed");
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_1_1_1_2_s_32),
             "1.1.1.2/32 removed");
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_1_1_2_0_s_24),
             "1.1.2.0/24 removed");

    /*
     * -3 entries and -1 shared path-list
     */
    FIB_TEST((0  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+4 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+4 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * An attached-host route. Expect to link to the incomplete adj
     */
    fib_prefix_t pfx_4_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 4.1.1.1/32 */
            .ip4.as_u32 = clib_host_to_net_u32(0x04010101),
        },
    };
    fib_table_entry_path_add(fib_index,
                             &pfx_4_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &zero_addr,
                             tm->hw[0]->sw_if_index,
                             fib_index,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_4_1_1_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "4.1.1.1/32 present");
    ai = fib_entry_get_adj(fei);

    ai2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                              VNET_LINK_IP4,
                              &pfx_4_1_1_1_s_32.fp_addr,
                              tm->hw[0]->sw_if_index);
    FIB_TEST((ai == ai2), "Attached-host link to incomplete ADJ");
    adj_unlock(ai2);

    /*
     * +1 entry and +1 shared path-list
     */
    FIB_TEST((1  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+5 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    fib_table_entry_delete(fib_index,
                           &pfx_4_1_1_1_s_32,
                           FIB_SOURCE_API);

    FIB_TEST((0  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+4 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+4 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * add a v6 prefix via v4 next-hops
     */
    fib_prefix_t pfx_2001_s_64 = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6.as_u64[0] = clib_host_to_net_u64(0x2001000000000000),
        },
    };
    fei = fib_table_entry_path_add(0, //default v6 table
                                   &pfx_2001_s_64,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(0, &pfx_2001_s_64);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "2001::/64 present");
    ai = fib_entry_get_adj(fei);
    adj = adj_get(ai);
    FIB_TEST((adj->lookup_next_index == IP_LOOKUP_NEXT_ARP),
             "2001::/64 via ARP-adj");
    FIB_TEST((adj->ia_link == VNET_LINK_IP6),
             "2001::/64 is link type v6");
    FIB_TEST((adj->ia_nh_proto == FIB_PROTOCOL_IP4),
             "2001::/64 ADJ-adj is NH proto v4");
    fib_table_entry_delete(0, &pfx_2001_s_64, FIB_SOURCE_API);

    /*
     * add a uRPF exempt prefix:
     *  test:
     *   - it's forwarding is drop
     *   - it's uRPF list is not empty
     *   - the uRPF list for the default route (it's cover) is empty
     */
    fei = fib_table_entry_special_add(fib_index,
                                      &pfx_4_1_1_1_s_32,
                                      FIB_SOURCE_URPF_EXEMPT,
                                      FIB_ENTRY_FLAG_DROP);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(load_balance_is_drop(dpo),
             "uRPF exempt 4.1.1.1/32 DROP");
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 1, 0),
             "uRPF list for exempt prefix has itf index 0");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_0_0_0_0_s_0);
    FIB_TEST(!fib_test_urpf_is_equal(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, 0),
             "uRPF list for 0.0.0.0/0 empty");

    fib_table_entry_delete(fib_index, &pfx_4_1_1_1_s_32, FIB_SOURCE_URPF_EXEMPT);

    /*
     * An adj-fib that fails the refinement criteria - no connected cover
     */
    fib_prefix_t pfx_12_10_10_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 12.10.10.2 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0c0a0a02),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_12_10_10_2_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_12_10_10_2_s_32.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_12_10_10_2_s_32);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_is_drop(dpo),
             "no connected cover adj-fib fails refinement: %U",
             format_dpo_id, dpo, 0);

    fib_table_entry_delete(fib_index,
                           &pfx_12_10_10_2_s_32,
                           FIB_SOURCE_ADJ);

    /*
     * An adj-fib that fails the refinement criteria - cover is connected
     * but on a different interface
     */
    fib_prefix_t pfx_10_10_10_127_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.127 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a7f),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_10_10_10_127_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_10_10_10_127_s_32.fp_addr,
                             tm->hw[1]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_127_s_32);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_is_drop(dpo),
             "wrong interface adj-fib fails refinement");

    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_127_s_32,
                           FIB_SOURCE_ADJ);

    /*
     * add a second path to an adj-fib
     * this is a sumiluation of another ARP entry created
     * on an interface on which the connected prefix does not exist.
     * The second path fails refinement. Expect to forward through the
     * first.
     */
    fib_prefix_t pfx_10_10_10_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.3 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a03),
        },
    };

    ai_03 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                VNET_LINK_IP4,
                                &nh_10_10_10_3,
                                tm->hw[0]->sw_if_index);

    fib_test_lb_bucket_t ip_o_10_10_10_3 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_03,
        },
    };
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_10_10_10_3_s_32,
                                   FIB_SOURCE_ADJ,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_3,
                                   tm->hw[0]->sw_if_index,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_10_10_10_3_s_32,
                                   FIB_SOURCE_ADJ,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_12_12_12_12,
                                   tm->hw[1]->sw_if_index,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_10_10_10_3),
             "10.10.10.3 via 10.10.10.3/Eth0 only");

    /*
     * remove the path that refines the cover, should go unresolved
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_10_10_10_3_s_32,
                                FIB_SOURCE_ADJ,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_3,
                                tm->hw[0]->sw_if_index,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_is_drop(dpo),
             "wrong interface adj-fib fails refinement");

    /*
     * add back the path that refines the cover
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_10_10_10_3_s_32,
                                   FIB_SOURCE_ADJ,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_3,
                                   tm->hw[0]->sw_if_index,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_10_10_10_3),
             "10.10.10.3 via 10.10.10.3/Eth0 only");

    /*
     * remove the path that does not refine the cover
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_10_10_10_3_s_32,
                                FIB_SOURCE_ADJ,
                                DPO_PROTO_IP4,
                                &nh_12_12_12_12,
                                tm->hw[1]->sw_if_index,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_10_10_10_3),
             "10.10.10.3 via 10.10.10.3/Eth0 only");

    /*
     * remove the path that does refine, it's the last path, so
     * the entry should be gone
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_10_10_10_3_s_32,
                                FIB_SOURCE_ADJ,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_3,
                                tm->hw[0]->sw_if_index,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_3_s_32);
    FIB_TEST((fei == FIB_NODE_INDEX_INVALID), "10.10.10.3 gone");

    adj_unlock(ai_03);

    /*
     * change the table's flow-hash config - expect the update to propagete to
     * the entries' load-balance objects
     */
    flow_hash_config_t old_hash_config, new_hash_config;

    old_hash_config = fib_table_get_flow_hash_config(fib_index,
                                                     FIB_PROTOCOL_IP4);
    new_hash_config = (IP_FLOW_HASH_SRC_ADDR |
                       IP_FLOW_HASH_DST_ADDR);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    lb = load_balance_get(dpo->dpoi_index);
    FIB_TEST((lb->lb_hash_config == old_hash_config),
             "Table and LB hash config match: %U",
             format_ip_flow_hash_config, lb->lb_hash_config);

    fib_table_set_flow_hash_config(fib_index, FIB_PROTOCOL_IP4, new_hash_config);

    FIB_TEST((lb->lb_hash_config == new_hash_config),
             "Table and LB newhash config match: %U",
             format_ip_flow_hash_config, lb->lb_hash_config);

    /*
     * A route via DVR DPO
     */
    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_10_10_10_3_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &zero_addr,
                                   tm->hw[0]->sw_if_index,
                                   ~0,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_DVR);
    dpo_id_t dvr_dpo = DPO_INVALID;
    dvr_dpo_add_or_lock(tm->hw[0]->sw_if_index, DPO_PROTO_IP4, &dvr_dpo);
    fib_test_lb_bucket_t ip_o_l2 = {
        .type = FT_LB_L2,
        .adj = {
            .adj = dvr_dpo.dpoi_index,
        },
    };

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_l2),
             "10.10.10.3 via L2 on Eth0");
    fib_table_entry_path_remove(fib_index,
                                &pfx_10_10_10_3_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &zero_addr,
                                tm->hw[0]->sw_if_index,
                                fib_index,
                                1,
                                FIB_ROUTE_PATH_DVR);
    dpo_reset(&dvr_dpo);

    /*
     * add the default route via a next-hop that will form a loop
     */
    fib_prefix_t pfx_conn = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 30.30.30.30 */
            .ip4.as_u32 = clib_host_to_net_u32(0x1e1e1e1e),
        },
    };

    dfrt = fib_table_entry_path_add(fib_index,
                                    &pfx_0_0_0_0_s_0,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &pfx_conn.fp_addr,
                                    ~0,
                                    fib_index,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    /*
     * the default route is a drop, since it's looped
     */
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(dfrt)),
             "Default route is DROP");

    /*
     * add a connected cover for the next-hop, this breaks the recursion loop
     * for the default route
     */
    fib_table_entry_path_add(fib_index,
                             &pfx_conn,
                             FIB_SOURCE_API,
                             (FIB_ENTRY_FLAG_CONNECTED |
                              FIB_ENTRY_FLAG_ATTACHED),
                             DPO_PROTO_IP4,
                             NULL,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    pfx_conn.fp_len = 32;
    fei = fib_table_lookup_exact_match(fib_index, &pfx_conn);

    u32 ai_30 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                    VNET_LINK_IP4,
                                    &pfx_conn.fp_addr,
                                    tm->hw[0]->sw_if_index);

    fib_test_lb_bucket_t ip_o_30_30_30_30 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_30,
        },
    };
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_30_30_30_30),
             "30.30.30.30 via adj");
    FIB_TEST_REC_FORW(&pfx_0_0_0_0_s_0, &pfx_conn, 0);

    pfx_conn.fp_len = 24;
    fib_table_entry_delete(fib_index,
                           &pfx_conn,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_0_0_0_0_s_0,
                           FIB_SOURCE_API);
    adj_unlock(ai_30);

    /*
     * CLEANUP
     *    remove adj-fibs:
     */
    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_1_s_32,
                           FIB_SOURCE_ADJ);
    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_2_s_32,
                           FIB_SOURCE_ADJ);
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32),
             "10.10.10.1/32 adj-fib removed");
    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_2_s_32),
             "10.10.10.2/32 adj-fib removed");

    /*
     * -2 entries and -2 non-shared path-list
     */
    FIB_TEST((0  == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR+2 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * unlock the adjacencies for which this test provided a rewrite.
     * These are the last locks on these adjs. they should thus go away.
     */
    adj_unlock(ai_02);
    adj_unlock(ai_01);
    adj_unlock(ai_12_12_12_12);

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    /*
     * CLEANUP
     *   remove the interface prefixes
     */
    local_pfx.fp_len = 32;
    fib_table_entry_special_remove(fib_index, &local_pfx,
                                   FIB_SOURCE_INTERFACE);
    fei = fib_table_lookup(fib_index, &local_pfx);

    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &local_pfx),
             "10.10.10.10/32 adj-fib removed");

    local_pfx.fp_len = 24;
    fib_table_entry_delete(fib_index, &local_pfx,
                           FIB_SOURCE_INTERFACE);

    FIB_TEST(FIB_NODE_INDEX_INVALID ==
             fib_table_lookup_exact_match(fib_index, &local_pfx),
             "10.10.10.10/24 adj-fib removed");

    /*
     * -2 entries and -2 non-shared path-list
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Last but not least, remove the VRF
     */
    FIB_TEST((0 == fib_table_get_num_entries(fib_index,
                                             FIB_PROTOCOL_IP4,
                                             FIB_SOURCE_API)),
             "NO API Source'd prefixes");
    FIB_TEST((0 == fib_table_get_num_entries(fib_index,
                                             FIB_PROTOCOL_IP4,
                                             FIB_SOURCE_RR)),
             "NO RR Source'd prefixes");
    FIB_TEST((0 == fib_table_get_num_entries(fib_index,
                                             FIB_PROTOCOL_IP4,
                                             FIB_SOURCE_INTERFACE)),
             "NO INterface Source'd prefixes");

    fib_table_unlock(fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_API);

    FIB_TEST((0  == fib_path_list_db_size()), "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNBR-5 == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENBR-5 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());
    FIB_TEST((ENBR-5 == pool_elts(fib_urpf_list_pool)), "uRPF pool size is %d",
             pool_elts(fib_urpf_list_pool));
    FIB_TEST((0 == pool_elts(load_balance_map_pool)), "LB-map pool size is %d",
             pool_elts(load_balance_map_pool));
    FIB_TEST((lb_count == pool_elts(load_balance_pool)), "LB pool size is %d",
             pool_elts(load_balance_pool));
    FIB_TEST((0 == pool_elts(dvr_dpo_pool)), "L2 DPO pool size is %d",
             pool_elts(dvr_dpo_pool));

    return (res);
}

static int
fib_test_v6 (void)
{
    /*
     * In the default table check for the presence and correct forwarding
     * of the special entries
     */
    fib_node_index_t dfrt, fei, ai, locked_ai, ai_01, ai_02;
    const dpo_id_t *dpo, *dpo_drop;
    const ip_adjacency_t *adj;
    const receive_dpo_t *rd;
    test_main_t *tm;
    u32 fib_index;
    int ii, res;

    res = 0;
    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    /* via 2001:0:0:1::2 */
    ip46_address_t nh_2001_2 = {
        .ip6 = {
            .as_u64 = {
                [0] = clib_host_to_net_u64(0x2001000000000001),
                [1] = clib_host_to_net_u64(0x0000000000000002),
            },
        },
    };

    tm = &test_main;

    dpo_drop = drop_dpo_get(DPO_PROTO_IP6);

    /* Find or create FIB table 11 */
    fib_index = fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP6, 11,
                                                  FIB_SOURCE_API);

    for (ii = 0; ii < 4; ii++)
    {
        ip6_main.fib_index_by_sw_if_index[tm->hw[ii]->sw_if_index] = fib_index;
    }

    fib_prefix_t pfx_0_0 = {
        .fp_len = 0,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                {0, 0},
            },
        },
    };

    dfrt = fib_table_lookup(fib_index, &pfx_0_0);
    FIB_TEST((FIB_NODE_INDEX_INVALID != dfrt), "default route present");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(dfrt)),
             "Default route is DROP");

    dpo = fib_entry_contribute_ip_forwarding(dfrt);
    FIB_TEST((dpo->dpoi_index == ip6_fib_table_fwding_lookup(
                  1,
                  &pfx_0_0.fp_addr.ip6)),
             "default-route; fwd and non-fwd tables match");

    // FIXME - check specials.

    /*
     * At this stage there is one v4 FIB with 5 routes and two v6 FIBs
     * each with 2 entries and a v6 mfib with 4 path-lists and v4 mfib with 2.
     * All entries are special so no path-list sharing.
     */
#define ENPS (5+4)
    u32 PNPS = (5+4+4+2);
    /*
     * if the IGMP plugin is loaded this adds two more entries to the v4 MFIB
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNPS == fib_path_list_pool_size()), "path list pool size is %d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * add interface routes.
     *  validate presence of /64 attached and /128 recieve.
     *  test for the presence of the receive address in the glean and local adj
     *
     * receive on 2001:0:0:1::1/128
     */
    fib_prefix_t local_pfx = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000001),
                    [1] = clib_host_to_net_u64(0x0000000000000001),
                },
            },
        }
    };

    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP6,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached interface route present");

    ai = fib_entry_get_adj(fei);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai), "attached interface route adj present");
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index),
             "attached interface adj is glean");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST((dpo->dpoi_index == ip6_fib_table_fwding_lookup(
                  1,
                  &local_pfx.fp_addr.ip6)),
             "attached-route; fwd and non-fwd tables match");

    local_pfx.fp_len = 128;
    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP6,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &local_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local interface route present");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST((DPO_RECEIVE == dpo->dpoi_type),
             "local interface adj is local");
    rd = receive_dpo_get(dpo->dpoi_index);

    FIB_TEST((0 == ip46_address_cmp(&local_pfx.fp_addr,
                                    &rd->rd_addr)),
             "local interface adj is receive ok");

    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST((dpo->dpoi_index == ip6_fib_table_fwding_lookup(
                  1,
                  &local_pfx.fp_addr.ip6)),
             "local-route; fwd and non-fwd tables match");
    FIB_TEST((0 == ip46_address_cmp(&local_pfx.fp_addr,
                                    &adj->sub_type.glean.rx_pfx.fp_addr)),
             "attached interface adj is receive ok");

    /*
     * +2 entries. +2 unshared path-lists
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB is empty");
    FIB_TEST((PNPS+2 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Modify the default route to be via an adj not yet known.
     * this sources the defalut route with the API source, which is
     * a higher preference to the DEFAULT_ROUTE source
     */
    fib_table_entry_path_add(fib_index, &pfx_0_0,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP6,
                             &nh_2001_2,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_0_0);

    FIB_TEST((fei == dfrt), "default route same index");
    ai = fib_entry_get_adj(fei);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai), "default route adj present");
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&nh_2001_2, &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    /*
     * find the adj in the shared db
     */
    locked_ai = adj_nbr_add_or_lock(FIB_PROTOCOL_IP6,
                                    VNET_LINK_IP6,
                                    &nh_2001_2,
                                    tm->hw[0]->sw_if_index);
    FIB_TEST((locked_ai == ai), "ADJ NBR DB find");
    adj_unlock(locked_ai);

    /*
     * no more entries. +1 shared path-list
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+3 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * remove the API source from the default route. We expected
     * the route to remain, sourced by DEFAULT_ROUTE, and hence a DROP
     */
    fib_table_entry_path_remove(fib_index, &pfx_0_0,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP6,
                                &nh_2001_2,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_0_0);

    FIB_TEST((fei == dfrt), "default route same index");
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(dfrt)),
             "Default route is DROP");

    /*
     * no more entries. -1 shared path-list
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+2 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add an 2 ARP entry => a complete ADJ plus adj-fib.
     */
    fib_prefix_t pfx_2001_1_2_s_128 = {
        .fp_len   = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr  = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000001),
                    [1] = clib_host_to_net_u64(0x0000000000000002),
                },
            },
        }
    };
    fib_prefix_t pfx_2001_1_3_s_128 = {
        .fp_len   = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr  = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000001),
                    [1] = clib_host_to_net_u64(0x0000000000000003),
                },
            },
        }
    };
    u8 eth_addr[] = {
        0xde, 0xde, 0xde, 0xba, 0xba, 0xba,
    };

    ai_01 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP6,
                                VNET_LINK_IP6,
                                &pfx_2001_1_2_s_128.fp_addr,
                                tm->hw[0]->sw_if_index);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai_01), "adj created");
    adj = adj_get(ai_01);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_2001_1_2_s_128.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    adj_nbr_update_rewrite(ai_01, ADJ_NBR_REWRITE_FLAG_COMPLETE,
                           fib_test_build_rewrite(eth_addr));
    FIB_TEST((IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index),
             "adj is complete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_2001_1_2_s_128.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    fib_table_entry_path_add(fib_index,
                             &pfx_2001_1_2_s_128,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP6,
                             &pfx_2001_1_2_s_128.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_2001_1_2_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "ADJ-FIB resolves via adj");

    eth_addr[5] = 0xb2;

    ai_02 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP6,
                                VNET_LINK_IP6,
                                &pfx_2001_1_3_s_128.fp_addr,
                                tm->hw[0]->sw_if_index);
    FIB_TEST((FIB_NODE_INDEX_INVALID != ai_02), "adj created");
    adj = adj_get(ai_02);
    FIB_TEST((IP_LOOKUP_NEXT_ARP == adj->lookup_next_index),
             "adj is incomplete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_2001_1_3_s_128.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");

    adj_nbr_update_rewrite(ai_02, ADJ_NBR_REWRITE_FLAG_COMPLETE,
                           fib_test_build_rewrite(eth_addr));
    FIB_TEST((IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index),
             "adj is complete");
    FIB_TEST((0 == ip46_address_cmp(&pfx_2001_1_3_s_128.fp_addr,
                                    &adj->sub_type.nbr.next_hop)),
             "adj nbr next-hop ok");
    FIB_TEST((ai_01 != ai_02), "ADJs are different");

    fib_table_entry_path_add(fib_index,
                             &pfx_2001_1_3_s_128,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP6,
                             &pfx_2001_1_3_s_128.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_2001_1_3_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_02 == ai), "ADJ-FIB resolves via adj");

    /*
     * +2 entries, +2 unshread path-lists.
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+4 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+4 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add a 2 routes via the first ADJ. ensure path-list sharing
     */
    fib_prefix_t pfx_2001_a_s_64 = {
        .fp_len   = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr  = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x200100000000000a),
                    [1] = clib_host_to_net_u64(0x0000000000000000),
                },
            },
        }
    };
    fib_prefix_t pfx_2001_b_s_64 = {
        .fp_len   = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr  = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x200100000000000b),
                    [1] = clib_host_to_net_u64(0x0000000000000000),
                },
            },
        }
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_2001_a_s_64,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP6,
                             &nh_2001_2,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_2001_a_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::a/64 resolves via 2001:0:0:1::1");
    fib_table_entry_path_add(fib_index,
                             &pfx_2001_b_s_64,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP6,
                             &nh_2001_2,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &pfx_2001_b_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::b/64 resolves via 2001:0:0:1::1");

    /*
     * +2 entries, +1 shared path-list.
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+5 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+6 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * add a v4 prefix via a v6 next-hop
     */
    fib_prefix_t pfx_1_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = 0x01010101,
        },
    };
    fei = fib_table_entry_path_add(0, // default table
                                   &pfx_1_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP6,
                                   &nh_2001_2,
                                   tm->hw[0]->sw_if_index,
                                   ~0,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(fei == fib_table_lookup_exact_match(0, &pfx_1_1_1_1_s_32),
             "1.1.1.1/32 o v6 route present");
    ai = fib_entry_get_adj(fei);
    adj = adj_get(ai);
    FIB_TEST((adj->lookup_next_index == IP_LOOKUP_NEXT_ARP),
             "1.1.1.1/32 via ARP-adj");
    FIB_TEST((adj->ia_link == VNET_LINK_IP4),
             "1.1.1.1/32 ADJ-adj is link type v4");
    FIB_TEST((adj->ia_nh_proto == FIB_PROTOCOL_IP6),
             "1.1.1.1/32 ADJ-adj is NH proto v6");
    fib_table_entry_delete(0, &pfx_1_1_1_1_s_32, FIB_SOURCE_API);

    /*
     * An attached route
     */
    fib_prefix_t pfx_2001_c_s_64 = {
        .fp_len   = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr  = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x200100000000000c),
                    [1] = clib_host_to_net_u64(0x0000000000000000),
                },
            },
        }
    };
    fib_table_entry_path_add(fib_index,
                             &pfx_2001_c_s_64,
                             FIB_SOURCE_CLI,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP6,
                             NULL,
                             tm->hw[0]->sw_if_index,
                             ~0,
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_c_s_64);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached route present");
    ai = fib_entry_get_adj(fei);
    adj = adj_get(ai);
    FIB_TEST((adj->lookup_next_index == IP_LOOKUP_NEXT_GLEAN),
             "2001:0:0:c/64 attached resolves via glean");

    fib_table_entry_path_remove(fib_index,
                                &pfx_2001_c_s_64,
                                FIB_SOURCE_CLI,
                                DPO_PROTO_IP6,
                                NULL,
                                tm->hw[0]->sw_if_index,
                                ~0,
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_c_s_64);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "attached route removed");

    /*
     * Shutdown the interface on which we have a connected and through
     * which the routes are reachable.
     * This will result in the connected, adj-fibs, and routes linking to drop
     * The local/for-us prefix continues to receive.
     */
    clib_error_t * error;

    error = vnet_sw_interface_set_flags(vnet_get_main(),
                                        tm->hw[0]->sw_if_index,
                                        ~VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    FIB_TEST((NULL == error), "Interface shutdown OK");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001::b/64 resolves via drop");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001::a/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::3/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::2/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::1/128 not drop");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1/64 resolves via drop");

    /*
     * no change
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+5 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+6 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * shutdown one of the other interfaces, then add a connected.
     * and swap one of the routes to it.
     */
    error = vnet_sw_interface_set_flags(vnet_get_main(),
                                        tm->hw[1]->sw_if_index,
                                        ~VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    FIB_TEST((NULL == error), "Interface 1 shutdown OK");

    fib_prefix_t connected_pfx = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                /* 2001:0:0:2::1/64 */
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000002),
                    [1] = clib_host_to_net_u64(0x0000000000000001),
                },
            },
        }
    };
    fib_table_entry_update_one_path(fib_index, &connected_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP6,
                                    NULL,
                                    tm->hw[1]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &connected_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached interface route present");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST(!dpo_cmp(dpo, dpo_drop),
             "2001:0:0:2/64 not resolves via drop");

    connected_pfx.fp_len = 128;
    fib_table_entry_update_one_path(fib_index, &connected_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP6,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup(fib_index, &connected_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local interface route present");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    dpo = load_balance_get_bucket(dpo->dpoi_index, 0);
    FIB_TEST((DPO_RECEIVE == dpo->dpoi_type),
             "local interface adj is local");
    rd = receive_dpo_get(dpo->dpoi_index);
    FIB_TEST((0 == ip46_address_cmp(&connected_pfx.fp_addr,
                                    &rd->rd_addr)),
             "local interface adj is receive ok");

    /*
     * +2 entries, +2 unshared path-lists
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+7 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+8 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());


    /*
     * bring the interface back up. we expected the routes to return
     * to normal forwarding.
     */
    error = vnet_sw_interface_set_flags(vnet_get_main(),
                                        tm->hw[0]->sw_if_index,
                                        VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    FIB_TEST((NULL == error), "Interface bring-up OK");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::a/64 resolves via 2001:0:0:1::1");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::b/64 resolves via 2001:0:0:1::1");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_02 == ai), "ADJ-FIB resolves via adj");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "ADJ-FIB resolves via adj");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    ai = fib_entry_get_adj(fei);
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index),
             "attached interface adj is glean");

    /*
     * Same test as above, but this time the HW interface goes down
     */
    error = vnet_hw_interface_set_flags(vnet_get_main(),
                                        tm->hw_if_indicies[0],
                                        ~VNET_HW_INTERFACE_FLAG_LINK_UP);
    FIB_TEST((NULL == error), "Interface shutdown OK");

    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001::b/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001::a/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::3/128 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::2/128 resolves via drop");
    local_pfx.fp_len = 128;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1::1/128 not drop");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(!dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "2001:0:0:1/64 resolves via drop");

    error = vnet_hw_interface_set_flags(vnet_get_main(),
                                        tm->hw_if_indicies[0],
                                        VNET_HW_INTERFACE_FLAG_LINK_UP);
    FIB_TEST((NULL == error), "Interface bring-up OK");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::a/64 resolves via 2001:0:0:1::1");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "2001::b/64 resolves via 2001:0:0:1::1");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_02 == ai), "ADJ-FIB resolves via adj");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    ai = fib_entry_get_adj(fei);
    FIB_TEST((ai_01 == ai), "ADJ-FIB resolves via adj");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    ai = fib_entry_get_adj(fei);
    adj = adj_get(ai);
    FIB_TEST((IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index),
             "attached interface adj is glean");

    /*
     * Delete the interface that the routes reolve through.
     * Again no routes are removed. They all point to drop.
     *
     * This is considered an error case. The control plane should
     * not remove interfaces through which routes resolve, but
     * such things can happen. ALL affected routes will drop.
     */
    vnet_delete_hw_interface(vnet_get_main(), tm->hw_if_indicies[0]);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001::b/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001::b/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::3/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::2/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::1/128 is drop");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1/64 resolves via drop");

    /*
     * no change
     */
    FIB_TEST((1 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS+7 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS+8 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * Add the interface back. routes stay unresolved.
     */
    error = ethernet_register_interface(vnet_get_main(),
                                        test_interface_device_class.index,
                                        0 /* instance */,
                                        hw_address,
                                        &tm->hw_if_indicies[0],
                                        /* flag change */ 0);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001::b/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001::b/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::3/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::2/64 resolves via drop");
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1::1/128 is drop");
    local_pfx.fp_len = 64;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "2001:0:0:1/64 resolves via drop");

    /*
     * CLEANUP ALL the routes
     */
    fib_table_entry_delete(fib_index,
                           &pfx_2001_c_s_64,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_2001_a_s_64,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_2001_b_s_64,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_2001_1_3_s_128,
                           FIB_SOURCE_ADJ);
    fib_table_entry_delete(fib_index,
                           &pfx_2001_1_2_s_128,
                           FIB_SOURCE_ADJ);
    local_pfx.fp_len = 64;
    fib_table_entry_delete(fib_index, &local_pfx,
                           FIB_SOURCE_INTERFACE);
    local_pfx.fp_len = 128;
    fib_table_entry_special_remove(fib_index, &local_pfx,
                                   FIB_SOURCE_INTERFACE);
    connected_pfx.fp_len = 64;
    fib_table_entry_delete(fib_index, &connected_pfx,
                           FIB_SOURCE_INTERFACE);
    connected_pfx.fp_len = 128;
    fib_table_entry_special_remove(fib_index, &connected_pfx,
                                   FIB_SOURCE_INTERFACE);

    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_2001_a_s_64)),
             "2001::a/64 removed");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_2001_b_s_64)),
             "2001::b/64 removed");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_2001_1_3_s_128)),
             "2001:0:0:1::3/128 removed");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &pfx_2001_1_2_s_128)),
             "2001:0:0:1::3/128 removed");
    local_pfx.fp_len = 64;
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &local_pfx)),
             "2001:0:0:1/64 removed");
    local_pfx.fp_len = 128;
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &local_pfx)),
             "2001:0:0:1::1/128 removed");
    connected_pfx.fp_len = 64;
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &connected_pfx)),
             "2001:0:0:2/64 removed");
    connected_pfx.fp_len = 128;
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup_exact_match(fib_index, &connected_pfx)),
             "2001:0:0:2::1/128 removed");

    /*
     * -8 entries. -7 path-lists (1 was shared).
     */
    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    /*
     * now remove the VRF
     */
    fib_table_unlock(fib_index, FIB_PROTOCOL_IP6, FIB_SOURCE_API);

    FIB_TEST((0 == fib_path_list_db_size()),   "path list DB population:%d",
             fib_path_list_db_size());
    FIB_TEST((PNPS-2 == fib_path_list_pool_size()), "path list pool size is%d",
             fib_path_list_pool_size());
    FIB_TEST((ENPS-2 == fib_entry_pool_size()), "entry pool size is %d",
             fib_entry_pool_size());

    adj_unlock(ai_02);
    adj_unlock(ai_01);

    /*
     * return the interfaces to up state
     */
    error = vnet_sw_interface_set_flags(vnet_get_main(),
                                        tm->hw[0]->sw_if_index,
                                        VNET_SW_INTERFACE_FLAG_ADMIN_UP);
    error = vnet_sw_interface_set_flags(vnet_get_main(),
                                        tm->hw[1]->sw_if_index,
                                        VNET_SW_INTERFACE_FLAG_ADMIN_UP);

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());
    FIB_TEST((0 == adj_glean_db_size()), "ADJ DB size is %d",
             adj_glean_db_size());

    return (res);
}

/*
 * Test Attached Exports
 */
static int
fib_test_ae (void)
{
    const dpo_id_t *dpo, *dpo_drop;
    const u32 fib_index = 0;
    fib_node_index_t fei;
    test_main_t *tm;
    ip4_main_t *im;
    int res;

    res = 0;
    tm = &test_main;
    im = &ip4_main;

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    /*
     * add interface routes. We'll assume this works. It's more rigorously
     * tested elsewhere.
     */
    fib_prefix_t local_pfx = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                /* 10.10.10.10 */
                .as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
            },
        },
    };

    vec_validate(im->fib_index_by_sw_if_index, tm->hw[0]->sw_if_index);
    im->fib_index_by_sw_if_index[tm->hw[0]->sw_if_index] = fib_index;

    dpo_drop = drop_dpo_get(DPO_PROTO_IP4);

    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "attached interface route present");

    local_pfx.fp_len = 32;
    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "local interface route present");

    /*
     * Add an 2 ARP entry => a complete ADJ plus adj-fib.
     */
    fib_prefix_t pfx_10_10_10_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.1 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
        },
    };
    fib_node_index_t ai;

    fib_table_entry_path_add(fib_index,
                             &pfx_10_10_10_1_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_10_10_10_1_s_32.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 created");
    ai = fib_entry_get_adj(fei);

    /*
     * create another FIB table into which routes will be imported
     */
    u32 import_fib_index1;

    import_fib_index1 = fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4,
                                                          11,
                                                          FIB_SOURCE_CLI);

    /*
     * Add an attached route in the import FIB
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(import_fib_index1,
                                    &local_pfx,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached export created");

    /*
     * check for the presence of the adj-fibs in the import table
     */
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 imported");
    FIB_TEST((ai == fib_entry_get_adj(fei)),
             "adj-fib1 Import uses same adj as export");

    /*
     * check for the presence of the local in the import table
     */
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local imported");

    /*
     * Add another adj-fin in the export table. Expect this
     * to get magically exported;
     */
    fib_prefix_t pfx_10_10_10_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.2 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_10_10_10_2_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_10_10_10_2_s_32.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 present");
    ai = fib_entry_get_adj(fei);

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 imported");
    FIB_TEST((ai == fib_entry_get_adj(fei)),
             "Import uses same adj as export");
    FIB_TEST((FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags(fei)),
             "ADJ-fib2 imported flags %d",
             fib_entry_get_flags(fei));

    /*
     * create a 2nd FIB table into which routes will be imported
     */
    u32 import_fib_index2;

    import_fib_index2 = fib_table_find_or_create_and_lock(FIB_PROTOCOL_IP4, 12,
                                                          FIB_SOURCE_CLI);

    /*
     * Add an attached route in the import FIB
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(import_fib_index2,
                                    &local_pfx,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached export created");

    /*
     * check for the presence of all the adj-fibs and local in the import table
     */
    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 imported");
    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 imported");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index2, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local imported");

    /*
     * add a 3rd adj-fib. expect it to be exported to both tables.
     */
    fib_prefix_t pfx_10_10_10_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.10.10.3 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a03),
        },
    };

    fib_table_entry_path_add(fib_index,
                             &pfx_10_10_10_3_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &pfx_10_10_10_3_s_32.fp_addr,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib3 present");
    ai = fib_entry_get_adj(fei);

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib3 imported to FIB1");
    FIB_TEST((ai == fib_entry_get_adj(fei)),
             "Import uses same adj as export");
    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib3 imported to FIB2");
    FIB_TEST((ai == fib_entry_get_adj(fei)),
             "Import uses same adj as export");

    /*
     * remove the 3rd adj fib. we expect it to be removed from both FIBs
     */
    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_3_s_32,
                           FIB_SOURCE_ADJ);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib3 remved");

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib3 removed from FIB1");

    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_3_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib3 removed from FIB2");

    /*
     * remove the attached route from the 2nd FIB. expect the imported
     * entries to be removed
     */
    local_pfx.fp_len = 24;
    fib_table_entry_delete(import_fib_index2,
                           &local_pfx,
                           FIB_SOURCE_API);
    fei = fib_table_lookup_exact_match(import_fib_index2, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "attached export removed");

    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib1 removed from FIB2");
    fei = fib_table_lookup_exact_match(import_fib_index2, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib2 removed from FIB2");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index2, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "local removed from FIB2");

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 still in FIB1");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 still in FIB1");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local still in FIB1");

    /*
     * modify the route in FIB1 so it is no longer attached. expect the imported
     * entries to be removed
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(import_fib_index1,
                                    &local_pfx,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &pfx_10_10_10_2_s_32.fp_addr,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib1 removed from FIB1");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib2 removed from FIB1");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "local removed from FIB1");

    /*
     * modify it back to attached. expect the adj-fibs back
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(import_fib_index1,
                                    &local_pfx,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 imported in FIB1");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 imported in FIB1");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local imported in FIB1");

    /*
     * add a covering attached next-hop for the interface address, so we have
     * a valid adj to find when we check the forwarding tables
     */
    fib_prefix_t pfx_10_0_0_0_s_8 = {
        .fp_len = 8,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            /* 10.0.0.0 */
            .ip4.as_u32 = clib_host_to_net_u32(0x0a000000),
        },
    };

    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_10_0_0_0_s_8,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &pfx_10_10_10_3_s_32.fp_addr,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          NULL,
                                          FIB_ROUTE_PATH_FLAG_NONE);
    dpo = fib_entry_contribute_ip_forwarding(fei);

    /*
     * remove the route in the export fib. expect the adj-fibs to be removed
     */
    local_pfx.fp_len = 24;
    fib_table_entry_delete(fib_index,
                           &local_pfx,
                           FIB_SOURCE_INTERFACE);

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "Delete export: ADJ-fib1 removed from FIB1");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib2 removed from FIB1");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "local removed from FIB1");

    /*
     * the adj-fibs in the export VRF are present in the FIB table,
     * but not installed in forwarding, since they have no attached cover.
     * Consequently a lookup in the MTRIE gives the adj for the covering
     * route 10.0.0.0/8.
     */
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 in export");

    index_t lbi;
    lbi = ip4_fib_forwarding_lookup(fib_index, &pfx_10_10_10_1_s_32.fp_addr.ip4);
    FIB_TEST(lbi == dpo->dpoi_index,
             "10.10.10.1 forwards on \n%U not \n%U",
             format_load_balance, lbi, 0,
             format_dpo_id, dpo, 0);
    lbi = ip4_fib_forwarding_lookup(fib_index, &pfx_10_10_10_2_s_32.fp_addr.ip4);
    FIB_TEST(lbi == dpo->dpoi_index,
             "10.10.10.2 forwards on %U", format_dpo_id, dpo, 0);
    lbi = ip4_fib_forwarding_lookup(fib_index, &pfx_10_10_10_3_s_32.fp_addr.ip4);
    FIB_TEST(lbi == dpo->dpoi_index,
             "10.10.10.3 forwards on %U", format_dpo_id, dpo, 0);

    /*
     * add the export prefix back, but not as attached.
     * No adj-fibs in export nor import tables
     */
    local_pfx.fp_len = 24;
    fei = fib_table_entry_update_one_path(fib_index,
                                          &local_pfx,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &pfx_10_10_10_1_s_32.fp_addr,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          NULL,
                                          FIB_ROUTE_PATH_FLAG_NONE);
    dpo = fib_entry_contribute_ip_forwarding(fei);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "non-attached in export: ADJ-fib1 in export");
    lbi = ip4_fib_forwarding_lookup(fib_index, &pfx_10_10_10_1_s_32.fp_addr.ip4);
    FIB_TEST(lbi == dpo->dpoi_index,
             "10.10.10.1 forwards on %U", format_dpo_id, dpo, 0);
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 in export");
    lbi = ip4_fib_forwarding_lookup(fib_index, &pfx_10_10_10_2_s_32.fp_addr.ip4);
    FIB_TEST(lbi == dpo->dpoi_index,
             "10.10.10.2 forwards on %U", format_dpo_id, dpo, 0);

    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib1 removed from FIB1");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "ADJ-fib2 removed from FIB1");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei), "local removed from FIB1");

    /*
     * modify the export prefix so it is attached. expect all covereds to return
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(fib_index,
                                    &local_pfx,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 reinstalled in export");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "Adj-fib1 is not drop in export");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 reinstalled in export");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local reinstalled in export");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached in export: ADJ-fib1 imported");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "Adj-fib1 is not drop in export: %U %U",
             format_dpo_id, dpo, 0,
             format_dpo_id, load_balance_get_bucket(dpo->dpoi_index, 0), 0);
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 imported");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 imported");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local imported");

    /*
     * modify the export prefix so connected. no change.
     */
    local_pfx.fp_len = 24;
    fib_table_entry_update_one_path(fib_index, &local_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib1 reinstalled in export");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "Adj-fib1 is not drop in export");
    fei = fib_table_lookup_exact_match(fib_index, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 reinstalled in export");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(fib_index, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local reinstalled in export");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "attached in export: ADJ-fib1 imported");
    dpo = fib_entry_contribute_ip_forwarding(fei);
    FIB_TEST(dpo_cmp(dpo_drop, load_balance_get_bucket(dpo->dpoi_index, 0)),
             "Adj-fib1 is not drop in export");
    fei = fib_table_lookup_exact_match(import_fib_index1, &pfx_10_10_10_2_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "ADJ-fib2 imported");
    local_pfx.fp_len = 32;
    fei = fib_table_lookup_exact_match(import_fib_index1, &local_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "local imported");

    /*
     * CLEANUP
     */
    fib_table_entry_delete(fib_index,
                           &pfx_10_0_0_0_s_8,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_1_s_32,
                           FIB_SOURCE_ADJ);
    fib_table_entry_delete(fib_index,
                           &pfx_10_10_10_2_s_32,
                           FIB_SOURCE_ADJ);
    local_pfx.fp_len = 32;
    fib_table_entry_delete(fib_index,
                           &local_pfx,
                           FIB_SOURCE_INTERFACE);
    local_pfx.fp_len = 24;
    fib_table_entry_delete(fib_index,
                           &local_pfx,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &local_pfx,
                           FIB_SOURCE_INTERFACE);
    local_pfx.fp_len = 24;
    fib_table_entry_delete(import_fib_index1,
                           &local_pfx,
                           FIB_SOURCE_API);

    fib_table_unlock(import_fib_index1, FIB_PROTOCOL_IP4, FIB_SOURCE_CLI);
    fib_table_unlock(import_fib_index2, FIB_PROTOCOL_IP4, FIB_SOURCE_CLI);

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    return (res);
}

/*
 * Test Path Preference
 */
static int
fib_test_pref (void)
{
    test_main_t *tm = &test_main;
    int res;

    res = 0;
    const fib_prefix_t pfx_1_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                .as_u32 = clib_host_to_net_u32(0x01010101),
            },
        },
    };

    /*
     * 2 high, 2 medium and 2 low preference non-recursive paths
     */
    fib_route_path_t nr_path_hi_1 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 0,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
        },
    };
    fib_route_path_t nr_path_hi_2 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[0]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 0,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
        },
    };
    fib_route_path_t nr_path_med_1 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[1]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 1,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0c01),
        },
    };
    fib_route_path_t nr_path_med_2 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[1]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 1,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0c01),
        },
    };
    fib_route_path_t nr_path_low_1 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[2]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 2,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0b01),
        },
    };
    fib_route_path_t nr_path_low_2 = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = tm->hw[2]->sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_preference = 2,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0b02),
        },
    };
    fib_route_path_t *nr_paths = NULL;

    vec_add1(nr_paths, nr_path_hi_1);
    vec_add1(nr_paths, nr_path_hi_2);
    vec_add1(nr_paths, nr_path_med_1);
    vec_add1(nr_paths, nr_path_med_2);
    vec_add1(nr_paths, nr_path_low_1);
    vec_add1(nr_paths, nr_path_low_2);

    adj_index_t ai_hi_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                              VNET_LINK_IP4,
                                              &nr_path_hi_1.frp_addr,
                                              nr_path_hi_1.frp_sw_if_index);
    adj_index_t ai_hi_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                              VNET_LINK_IP4,
                                              &nr_path_hi_2.frp_addr,
                                              nr_path_hi_2.frp_sw_if_index);
    adj_index_t ai_med_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                               VNET_LINK_IP4,
                                               &nr_path_med_1.frp_addr,
                                               nr_path_med_1.frp_sw_if_index);
    adj_index_t ai_med_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                               VNET_LINK_IP4,
                                               &nr_path_med_2.frp_addr,
                                               nr_path_med_2.frp_sw_if_index);
    adj_index_t ai_low_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                               VNET_LINK_IP4,
                                               &nr_path_low_1.frp_addr,
                                               nr_path_low_1.frp_sw_if_index);
    adj_index_t ai_low_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                               VNET_LINK_IP4,
                                               &nr_path_low_2.frp_addr,
                                               nr_path_low_2.frp_sw_if_index);

    fib_test_lb_bucket_t ip_hi_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_hi_1,
        },
    };
    fib_test_lb_bucket_t ip_hi_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_hi_2,
        },
    };
    fib_test_lb_bucket_t ip_med_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_med_1,
        },
    };
    fib_test_lb_bucket_t ip_med_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_med_2,
        },
    };
    fib_test_lb_bucket_t ip_low_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_low_1,
        },
    };
    fib_test_lb_bucket_t ip_low_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_low_2,
        },
    };

    fib_node_index_t fei;

    fei = fib_table_entry_path_add2(0,
                                    &pfx_1_1_1_1_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    nr_paths);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &ip_hi_1,
                                      &ip_hi_2),
             "1.1.1.1/32 via high preference paths");

    /*
     * bring down the interface on which the high preference path lie
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[0]->sw_if_index,
                                0);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &ip_med_1,
                                      &ip_med_2),
             "1.1.1.1/32 via medium preference paths");

    /*
     * bring down the interface on which the medium preference path lie
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[1]->sw_if_index,
                                0);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &ip_low_1,
                                      &ip_low_2),
             "1.1.1.1/32 via low preference paths");

    /*
     * bring up the interface on which the high preference path lie
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[0]->sw_if_index,
                                VNET_SW_INTERFACE_FLAG_ADMIN_UP);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &ip_hi_1,
                                      &ip_hi_2),
             "1.1.1.1/32 via high preference paths");

    /*
     * bring up the interface on which the medium preference path lie
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[1]->sw_if_index,
                                VNET_SW_INTERFACE_FLAG_ADMIN_UP);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &ip_hi_1,
                                      &ip_hi_2),
             "1.1.1.1/32 via high preference paths");

    dpo_id_t ip_1_1_1_1 = DPO_INVALID;
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1_1_1_1);

    /*
     * 3 recursive paths of different preference
     */
    const fib_prefix_t pfx_1_1_1_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                .as_u32 = clib_host_to_net_u32(0x01010102),
            },
        },
    };
    const fib_prefix_t pfx_1_1_1_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                .as_u32 = clib_host_to_net_u32(0x01010103),
            },
        },
    };
    fei = fib_table_entry_path_add2(0,
                                    &pfx_1_1_1_2_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    nr_paths);
    dpo_id_t ip_1_1_1_2 = DPO_INVALID;
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1_1_1_2);
    fei = fib_table_entry_path_add2(0,
                                    &pfx_1_1_1_3_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    nr_paths);
    dpo_id_t ip_1_1_1_3 = DPO_INVALID;
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1_1_1_3);

    fib_test_lb_bucket_t ip_o_1_1_1_1 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = ip_1_1_1_1.dpoi_index,
        },
    };
    fib_test_lb_bucket_t ip_o_1_1_1_2 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = ip_1_1_1_2.dpoi_index,
        },
    };
    fib_test_lb_bucket_t ip_o_1_1_1_3 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = ip_1_1_1_3.dpoi_index,
        },
    };
    fib_route_path_t r_path_hi = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = ~0,
        .frp_fib_index = 0,
        .frp_weight = 1,
        .frp_preference = 0,
        .frp_flags = FIB_ROUTE_PATH_RESOLVE_VIA_HOST,
        .frp_addr = pfx_1_1_1_1_s_32.fp_addr,
    };
    fib_route_path_t r_path_med = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = ~0,
        .frp_fib_index = 0,
        .frp_weight = 1,
        .frp_preference = 10,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_addr = pfx_1_1_1_2_s_32.fp_addr,
    };
    fib_route_path_t r_path_low = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_sw_if_index = ~0,
        .frp_fib_index = 0,
        .frp_weight = 1,
        .frp_preference = 255,
        .frp_flags = FIB_ROUTE_PATH_RESOLVE_VIA_HOST,
        .frp_addr = pfx_1_1_1_3_s_32.fp_addr,
    };
    fib_route_path_t *r_paths = NULL;

    vec_add1(r_paths, r_path_hi);
    vec_add1(r_paths, r_path_low);
    vec_add1(r_paths, r_path_med);

    /*
     * add many recursive so we get the LB MAp created
     */
#define N_PFXS 64
    fib_prefix_t pfx_r[N_PFXS];
    unsigned int n_pfxs;
    for (n_pfxs = 0; n_pfxs < N_PFXS; n_pfxs++)
    {
        pfx_r[n_pfxs].fp_len = 32;
        pfx_r[n_pfxs].fp_proto = FIB_PROTOCOL_IP4;
        pfx_r[n_pfxs].fp_addr.ip4.as_u32 =
            clib_host_to_net_u32(0x02000000 + n_pfxs);

        fei = fib_table_entry_path_add2(0,
                                        &pfx_r[n_pfxs],
                                        FIB_SOURCE_API,
                                        FIB_ENTRY_FLAG_NONE,
                                        r_paths);

        FIB_TEST(!fib_test_validate_entry(fei,
                                          FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                          1,
                                          &ip_o_1_1_1_1),
                 "recursive via high preference paths");

        /*
         * withdraw hig pref resolving entry
         */
        fib_table_entry_delete(0,
                               &pfx_1_1_1_1_s_32,
                               FIB_SOURCE_API);

        /* suspend so the update walk kicks int */
        vlib_process_suspend(vlib_get_main(), 1e-5);

        FIB_TEST(!fib_test_validate_entry(fei,
                                          FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                          1,
                                          &ip_o_1_1_1_2),
                 "recursive via medium preference paths");

        /*
         * withdraw medium pref resolving entry
         */
        fib_table_entry_delete(0,
                               &pfx_1_1_1_2_s_32,
                               FIB_SOURCE_API);

        /* suspend so the update walk kicks int */
        vlib_process_suspend(vlib_get_main(), 1e-5);

        FIB_TEST(!fib_test_validate_entry(fei,
                                          FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                          1,
                                          &ip_o_1_1_1_3),
                 "recursive via low preference paths");

        /*
         * add back paths for next iteration
         */
        fei = fib_table_entry_update(0,
                                     &pfx_1_1_1_2_s_32,
                                     FIB_SOURCE_API,
                                     FIB_ENTRY_FLAG_NONE,
                                     nr_paths);
        fei = fib_table_entry_update(0,
                                     &pfx_1_1_1_1_s_32,
                                     FIB_SOURCE_API,
                                     FIB_ENTRY_FLAG_NONE,
                                     nr_paths);

        /* suspend so the update walk kicks int */
        vlib_process_suspend(vlib_get_main(), 1e-5);

        fei = fib_table_lookup_exact_match(0, &pfx_r[n_pfxs]);
        FIB_TEST(!fib_test_validate_entry(fei,
                                          FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                          1,
                                          &ip_o_1_1_1_1),
                 "recursive via high preference paths");
    }


    fib_table_entry_delete(0,
                           &pfx_1_1_1_1_s_32,
                           FIB_SOURCE_API);

    /* suspend so the update walk kicks int */
    vlib_process_suspend(vlib_get_main(), 1e-5);

    for (n_pfxs = 0; n_pfxs < N_PFXS; n_pfxs++)
    {
        fei = fib_table_lookup_exact_match(0, &pfx_r[n_pfxs]);

        FIB_TEST(!fib_test_validate_entry(fei,
                                          FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                          1,
                                          &ip_o_1_1_1_2),
                 "recursive via medium preference paths");
    }
    for (n_pfxs = 0; n_pfxs < N_PFXS; n_pfxs++)
    {
        fib_table_entry_delete(0,
                               &pfx_r[n_pfxs],
                               FIB_SOURCE_API);
    }

    /*
     * Cleanup
     */
    fib_table_entry_delete(0,
                           &pfx_1_1_1_2_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(0,
                           &pfx_1_1_1_3_s_32,
                           FIB_SOURCE_API);

    dpo_reset(&ip_1_1_1_1);
    dpo_reset(&ip_1_1_1_2);
    dpo_reset(&ip_1_1_1_3);
    adj_unlock(ai_low_2);
    adj_unlock(ai_low_1);
    adj_unlock(ai_med_2);
    adj_unlock(ai_med_1);
    adj_unlock(ai_hi_2);
    adj_unlock(ai_hi_1);

    return (res);
}

/*
 * Test the recursive route route handling for GRE tunnels
 */
static int
fib_test_label (void)
{
    fib_node_index_t fei, ai_mpls_10_10_10_1, ai_v4_10_10_11_1, ai_v4_10_10_11_2, ai_mpls_10_10_11_2, ai_mpls_10_10_11_1;
    const u32 fib_index = 0;
    int lb_count, ii, res;
    test_main_t *tm;
    ip4_main_t *im;

    res = 0;
    lb_count = pool_elts(load_balance_pool);
    tm = &test_main;
    im = &ip4_main;

    /*
     * add interface routes. We'll assume this works. It's more rigorously
     * tested elsewhere.
     */
    fib_prefix_t local0_pfx = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                /* 10.10.10.10 */
                .as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
            },
        },
    };

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    vec_validate(im->fib_index_by_sw_if_index, tm->hw[0]->sw_if_index);
    im->fib_index_by_sw_if_index[tm->hw[0]->sw_if_index] = fib_index;

    fib_table_entry_update_one_path(fib_index, &local0_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local0_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "attached interface route present");

    local0_pfx.fp_len = 32;
    fib_table_entry_update_one_path(fib_index, &local0_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local0_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "local interface route present");

    fib_prefix_t local1_pfx = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4 = {
                /* 10.10.11.10 */
                .as_u32 = clib_host_to_net_u32(0x0a0a0b0a),
            },
        },
    };

    vec_validate(im->fib_index_by_sw_if_index, tm->hw[1]->sw_if_index);
    im->fib_index_by_sw_if_index[tm->hw[1]->sw_if_index] = fib_index;

    fib_table_entry_update_one_path(fib_index, &local1_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_ATTACHED),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[1]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local1_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "attached interface route present");

    local1_pfx.fp_len = 32;
    fib_table_entry_update_one_path(fib_index, &local1_pfx,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[1]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(fib_index, &local1_pfx);

    FIB_TEST((FIB_NODE_INDEX_INVALID != fei),
             "local interface route present");

    ip46_address_t nh_10_10_10_1 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x0a0a0a01),
        },
    };
    ip46_address_t nh_10_10_11_1 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x0a0a0b01),
        },
    };
    ip46_address_t nh_10_10_11_2 = {
        .ip4 = {
            .as_u32 = clib_host_to_net_u32(0x0a0a0b02),
        },
    };

    ai_v4_10_10_11_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                           VNET_LINK_IP4,
                                           &nh_10_10_11_1,
                                           tm->hw[1]->sw_if_index);
    ai_v4_10_10_11_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                           VNET_LINK_IP4,
                                           &nh_10_10_11_2,
                                           tm->hw[1]->sw_if_index);
    ai_mpls_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_10_1,
                                             tm->hw[0]->sw_if_index);
    ai_mpls_10_10_11_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_11_2,
                                             tm->hw[1]->sw_if_index);
    ai_mpls_10_10_11_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_11_1,
                                             tm->hw[1]->sw_if_index);

    /*
     * Add an etry with one path with a real out-going label
     */
    fib_prefix_t pfx_1_1_1_1_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010101),
        },
    };
    fib_test_lb_bucket_t l99_eos_o_10_10_10_1 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .adj = ai_mpls_10_10_10_1,
            .label = 99,
            .eos = MPLS_EOS,
        },
    };
    fib_test_lb_bucket_t l99_neos_o_10_10_10_1 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .adj = ai_mpls_10_10_10_1,
            .label = 99,
            .eos = MPLS_NON_EOS,
        },
    };
    fib_mpls_label_t *l99 = NULL, fml99 = {
        .fml_value = 99,
    };
    vec_add1(l99, fml99);

    fib_table_entry_update_one_path(fib_index,
                                    &pfx_1_1_1_1_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1,
                                    l99,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST((FIB_NODE_INDEX_INVALID != fei), "1.1.1.1/32 created");

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_eos_o_10_10_10_1),
             "1.1.1.1/32 LB 1 bucket via label 99 over 10.10.10.1");

    /*
     * add a path with an implicit NULL label
     */
    fib_test_lb_bucket_t a_o_10_10_11_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_v4_10_10_11_1,
        },
    };
    fib_test_lb_bucket_t a_mpls_o_10_10_11_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_mpls_10_10_11_1,
        },
    };
    fib_mpls_label_t *l_imp_null = NULL, fml_imp_null = {
        .fml_value =  MPLS_IETF_IMPLICIT_NULL_LABEL,
    };
    vec_add1(l_imp_null, fml_imp_null);

    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_1_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_11_1,
                                   tm->hw[1]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   l_imp_null,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &a_o_10_10_11_1),
             "1.1.1.1/32 LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj over 10.10.11.1");

    /*
     * assign the route a local label
     */
    fib_table_entry_local_label_add(fib_index,
                                    &pfx_1_1_1_1_s_32,
                                    24001);

    fib_prefix_t pfx_24001_eos = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 24001,
        .fp_eos = MPLS_EOS,
    };
    fib_prefix_t pfx_24001_neos = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 24001,
        .fp_eos = MPLS_NON_EOS,
    };
    fib_test_lb_bucket_t disp_o_10_10_11_1 = {
	.type = FT_LB_MPLS_DISP_PIPE_O_ADJ,
	.adj = {
	    .adj = ai_v4_10_10_11_1,
	},
    };

    /*
     * The EOS entry should link to both the paths,
     *  and use an ip adj for the imp-null
     * The NON-EOS entry should link to both the paths,
     *  and use an mpls adj for the imp-null
     */
    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &disp_o_10_10_11_1),
             "24001/eos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "mpls disp adj over 10.10.11.1");


    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      2,
                                      &l99_neos_o_10_10_10_1,
                                      &a_mpls_o_10_10_11_1),
             "24001/neos LB 1 bucket via: "
             "label 99 over 10.10.10.1 ",
             "mpls-adj via 10.10.11.1");

    /*
     * add an unlabelled path, this is excluded from the neos chains,
     */
    fib_test_lb_bucket_t adj_o_10_10_11_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_v4_10_10_11_2,
        },
    };
    fib_test_lb_bucket_t disp_o_10_10_11_2 = {
	.type = FT_LB_MPLS_DISP_PIPE_O_ADJ,
	.adj = {
	    .adj = ai_v4_10_10_11_2,
	},
    };


    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_1_1_1_1_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_11_2,
                                   tm->hw[1]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      16, // 3 choices spread over 16 buckets
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 16 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj over 10.10.11.1",
             "adj over 10.10.11.2");

    /*
     * get and lock a reference to the non-eos of the via entry 1.1.1.1/32
     */
    dpo_id_t non_eos_1_1_1_1 = DPO_INVALID;
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &non_eos_1_1_1_1);

    /*
     * n-eos has only the 2 labelled paths
     */
    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      2,
                                      &l99_neos_o_10_10_10_1,
                                      &a_mpls_o_10_10_11_1),
             "24001/neos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj-mpls over 10.10.11.2");

    /*
     * A labelled recursive
     */
    fib_prefix_t pfx_2_2_2_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020202),
        },
    };
    fib_test_lb_bucket_t l1600_eos_o_1_1_1_1 = {
	.type = FT_LB_LABEL_O_LB,
	.label_o_lb = {
	    .lb = non_eos_1_1_1_1.dpoi_index,
	    .label = 1600,
	    .eos = MPLS_EOS,
            .mode = FIB_MPLS_LSP_MODE_UNIFORM,
	},
    };
    fib_mpls_label_t *l1600 = NULL, fml1600 = {
        .fml_value = 1600,
        .fml_mode = FIB_MPLS_LSP_MODE_UNIFORM,
    };
    vec_add1(l1600, fml1600);

    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_2_2_2_2_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &pfx_1_1_1_1_s_32.fp_addr,
                                          ~0,
                                          fib_index,
                                          1,
                                          l1600,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l1600_eos_o_1_1_1_1),
	     "2.2.2.2.2/32 LB 1 buckets via: "
	     "label 1600 over 1.1.1.1");

    dpo_id_t dpo_44 = DPO_INVALID;
    index_t urpfi;

    fib_entry_contribute_forwarding(fei, FIB_FORW_CHAIN_TYPE_UNICAST_IP4, &dpo_44);
    urpfi = load_balance_get_urpf(dpo_44.dpoi_index);

    FIB_TEST(fib_urpf_check(urpfi, tm->hw[0]->sw_if_index),
             "uRPF check for 2.2.2.2/32 on %d OK",
             tm->hw[0]->sw_if_index);
    FIB_TEST(fib_urpf_check(urpfi, tm->hw[1]->sw_if_index),
             "uRPF check for 2.2.2.2/32 on %d OK",
             tm->hw[1]->sw_if_index);
    FIB_TEST(!fib_urpf_check(urpfi, 99),
             "uRPF check for 2.2.2.2/32 on 99 not-OK",
             99);

    fib_entry_contribute_forwarding(fei, FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS, &dpo_44);
    FIB_TEST(urpfi == load_balance_get_urpf(dpo_44.dpoi_index),
             "Shared uRPF on IP and non-EOS chain");

    dpo_reset(&dpo_44);

    /*
     * we are holding a lock on the non-eos LB of the via-entry.
     * do a PIC-core failover by shutting the link of the via-entry.
     *
     * shut down the link with the valid label
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[0]->sw_if_index,
                                0);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &a_o_10_10_11_1,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 2 buckets via: "
             "adj over 10.10.11.1, ",
             "adj-v4 over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_2),
             "24001/eos LB 2 buckets via: "
             "mpls-disp adj over 10.10.11.1, ",
             "mpls-disp adj-v4 over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &a_mpls_o_10_10_11_1),
             "24001/neos LB 1 buckets via: "
             "adj-mpls over 10.10.11.2");

    /*
     * test that the pre-failover load-balance has been in-place
     * modified
     */
    dpo_id_t current = DPO_INVALID;
    fib_entry_contribute_forwarding(fei,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &current);

    FIB_TEST(!dpo_cmp(&non_eos_1_1_1_1,
                      &current),
             "PIC-core LB inplace modified %U %U",
             format_dpo_id, &non_eos_1_1_1_1, 0,
             format_dpo_id, &current, 0);

    dpo_reset(&non_eos_1_1_1_1);
    dpo_reset(&current);

    /*
     * no-shut the link with the valid label
     */
    vnet_sw_interface_set_flags(vnet_get_main(),
                                tm->hw[0]->sw_if_index,
                                VNET_SW_INTERFACE_FLAG_ADMIN_UP);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      16, // 3 choices spread over 16 buckets
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &a_o_10_10_11_1,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 16 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj over 10.10.11.1",
             "adj-v4 over 10.10.11.2");


    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      16, // 3 choices spread over 16 buckets
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &l99_eos_o_10_10_10_1,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_2,
                                      &disp_o_10_10_11_2,
                                      &disp_o_10_10_11_2,
                                      &disp_o_10_10_11_2,
                                      &disp_o_10_10_11_2),
             "24001/eos LB 16 buckets via: "
             "label 99 over 10.10.10.1, "
             "MPLS disp adj over 10.10.11.1",
             "MPLS disp adj-v4 over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      2,
                                      &l99_neos_o_10_10_10_1,
                                      &a_mpls_o_10_10_11_1),
             "24001/neos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj-mpls over 10.10.11.2");

    /*
     * remove the first path with the valid label
     */
    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_10_1,
                                tm->hw[0]->sw_if_index,
                                ~0, // invalid fib index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &a_o_10_10_11_1,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 2 buckets via: "
             "adj over 10.10.11.1, "
             "adj-v4 over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &disp_o_10_10_11_1,
                                      &disp_o_10_10_11_2),
             "24001/eos LB 2 buckets via: "
             "MPLS disp adj over 10.10.11.1, "
             "MPLS disp adj-v4 over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &a_mpls_o_10_10_11_1),
             "24001/neos LB 1 buckets via: "
             "adj-mpls over 10.10.11.2");

    /*
     * remove the other path with a valid label
     */
    fib_test_lb_bucket_t bucket_drop = {
        .type = FT_LB_DROP,
    };
    fib_test_lb_bucket_t mpls_bucket_drop = {
        .type = FT_LB_DROP,
        .special = {
            .adj = DPO_PROTO_MPLS,
        },
    };

    fib_table_entry_path_remove(fib_index,
                                &pfx_1_1_1_1_s_32,
                                FIB_SOURCE_API,
                                DPO_PROTO_IP4,
                                &nh_10_10_11_1,
                                tm->hw[1]->sw_if_index,
                                ~0, // invalid fib index
                                1,
                                FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 1 buckets via: "
             "adj over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      1,
                                      &disp_o_10_10_11_2),
             "24001/eos LB 1 buckets via: "
             "MPLS disp adj over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &mpls_bucket_drop),
             "24001/neos LB 1 buckets via: DROP");

    /*
     * add back the path with the valid label
     */
    l99 = NULL;
    vec_add1(l99, fml99);

    fib_table_entry_path_add(fib_index,
                             &pfx_1_1_1_1_s_32,
                             FIB_SOURCE_API,
                             FIB_ENTRY_FLAG_NONE,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_1,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             l99,
                             FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &adj_o_10_10_11_2),
             "1.1.1.1/32 LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &disp_o_10_10_11_2),
             "24001/eos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "MPLS disp adj over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_24001_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &l99_neos_o_10_10_10_1),
             "24001/neos LB 1 buckets via: "
             "label 99 over 10.10.10.1");

    /*
     * change the local label
     */
    fib_table_entry_local_label_add(fib_index,
                                    &pfx_1_1_1_1_s_32,
                                    25005);

    fib_prefix_t pfx_25005_eos = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 25005,
        .fp_eos = MPLS_EOS,
    };
    fib_prefix_t pfx_25005_neos = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 25005,
        .fp_eos = MPLS_NON_EOS,
    };

    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup(fib_index, &pfx_24001_eos)),
             "24001/eos removed after label change");
    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              fib_table_lookup(fib_index, &pfx_24001_neos)),
             "24001/eos removed after label change");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_25005_eos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &disp_o_10_10_11_2),
             "25005/eos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "MPLS disp adj over 10.10.11.2");

    fei = fib_table_lookup(MPLS_FIB_DEFAULT_TABLE_ID,
                           &pfx_25005_neos);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &l99_neos_o_10_10_10_1),
             "25005/neos LB 1 buckets via: "
             "label 99 over 10.10.10.1");

    /*
     * remove the local label.
     * the check that the MPLS entries are gone is done by the fact the
     * MPLS table is no longer present.
     */
    fib_table_entry_local_label_remove(fib_index,
                                       &pfx_1_1_1_1_s_32,
                                       25005);

    fei = fib_table_lookup(fib_index, &pfx_1_1_1_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &l99_eos_o_10_10_10_1,
                                      &adj_o_10_10_11_2),
             "24001/eos LB 2 buckets via: "
             "label 99 over 10.10.10.1, "
             "adj over 10.10.11.2");

    FIB_TEST((FIB_NODE_INDEX_INVALID ==
              mpls_fib_index_from_table_id(MPLS_FIB_DEFAULT_TABLE_ID)),
             "No more MPLS FIB entries => table removed");

    /*
     * add another via-entry for the recursive
     */
    fib_prefix_t pfx_1_1_1_2_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x01010102),
        },
    };
    fib_test_lb_bucket_t l101_eos_o_10_10_10_1 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .adj = ai_mpls_10_10_10_1,
            .label = 101,
            .eos = MPLS_EOS,
        },
    };
    fib_mpls_label_t *l101 = NULL, fml101 = {
        .fml_value = 101,
    };
    vec_add1(l101, fml101);

    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_1_1_1_2_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_10_1,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          l101,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l101_eos_o_10_10_10_1),
             "1.1.1.2/32 LB 1 buckets via: "
             "label 101 over 10.10.10.1");

    dpo_id_t non_eos_1_1_1_2 = DPO_INVALID;
    fib_entry_contribute_forwarding(fib_table_lookup(fib_index,
                                                     &pfx_1_1_1_1_s_32),
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &non_eos_1_1_1_1);
    fib_entry_contribute_forwarding(fib_table_lookup(fib_index,
                                                     &pfx_1_1_1_2_s_32),
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &non_eos_1_1_1_2);

    fib_test_lb_bucket_t l1601_eos_o_1_1_1_2 = {
        .type = FT_LB_LABEL_O_LB,
        .label_o_lb = {
            .lb = non_eos_1_1_1_2.dpoi_index,
            .label = 1601,
            .eos = MPLS_EOS,
        },
    };
    fib_mpls_label_t *l1601 = NULL, fml1601 = {
        .fml_value = 1601,
    };
    vec_add1(l1601, fml1601);

    l1600_eos_o_1_1_1_1.label_o_lb.lb = non_eos_1_1_1_1.dpoi_index;

    fei = fib_table_entry_path_add(fib_index,
                                   &pfx_2_2_2_2_s_32,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &pfx_1_1_1_2_s_32.fp_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   l1601,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &l1600_eos_o_1_1_1_1,
                                      &l1601_eos_o_1_1_1_2),
             "2.2.2.2/32 LB 2 buckets via: "
             "label 1600 via 1.1,1.1, "
             "label 16001 via 1.1.1.2");

    /*
     * update the via-entry so it no longer has an imp-null path.
     * the LB for the recursive can use an imp-null
     */
    l_imp_null = NULL;
    vec_add1(l_imp_null, fml_imp_null);

    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_1_1_1_2_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_11_1,
                                          tm->hw[1]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          l_imp_null,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &a_o_10_10_11_1),
             "1.1.1.2/32 LB 1 buckets via: "
             "adj 10.10.11.1");

    fei = fib_table_lookup(fib_index, &pfx_2_2_2_2_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &l1600_eos_o_1_1_1_1,
                                      &l1601_eos_o_1_1_1_2),
             "2.2.2.2/32 LB 2 buckets via: "
             "label 1600 via 1.1,1.1, "
             "label 16001 via 1.1.1.2");

    /*
     * update the via-entry so it no longer has labelled paths.
     * the LB for the recursive should exclue this via form its LB
     */
    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_1_1_1_2_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_11_1,
                                          tm->hw[1]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          NULL,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &a_o_10_10_11_1),
             "1.1.1.2/32 LB 1 buckets via: "
             "adj 10.10.11.1");

    fei = fib_table_lookup(fib_index, &pfx_2_2_2_2_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l1600_eos_o_1_1_1_1),
             "2.2.2.2/32 LB 1 buckets via: "
             "label 1600 via 1.1,1.1");

    dpo_reset(&non_eos_1_1_1_1);
    dpo_reset(&non_eos_1_1_1_2);

    /*
     * Add a recursive with no out-labels. We expect to use the IP of the via
     */
    fib_prefix_t pfx_2_2_2_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020203),
        },
    };
    dpo_id_t ip_1_1_1_1 = DPO_INVALID;

    fib_table_entry_update_one_path(fib_index,
                                    &pfx_2_2_2_3_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &pfx_1_1_1_1_s_32.fp_addr,
                                    ~0,
                                    fib_index,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fib_entry_contribute_forwarding(fib_table_lookup(fib_index,
                                                     &pfx_1_1_1_1_s_32),
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1_1_1_1);

    fib_test_lb_bucket_t ip_o_1_1_1_1 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = ip_1_1_1_1.dpoi_index,
        },
    };

    fei = fib_table_lookup(fib_index, &pfx_2_2_2_3_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_1_1_1_1),
             "2.2.2.2.3/32 LB 1 buckets via: "
             "ip 1.1.1.1");

    /*
     * Add a recursive with an imp-null out-label.
     * We expect to use the IP of the via
     */
    fib_prefix_t pfx_2_2_2_4_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020204),
        },
    };

    fib_table_entry_update_one_path(fib_index,
                                    &pfx_2_2_2_4_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &pfx_1_1_1_1_s_32.fp_addr,
                                    ~0,
                                    fib_index,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup(fib_index, &pfx_2_2_2_4_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_1_1_1_1),
             "2.2.2.2.4/32 LB 1 buckets via: "
             "ip 1.1.1.1");

    dpo_reset(&ip_1_1_1_1);

    /*
     * Create an entry with a deep label stack
     */
    fib_prefix_t pfx_2_2_5_5_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020505),
        },
    };
    fib_test_lb_bucket_t ls_eos_o_10_10_10_1 = {
        .type = FT_LB_LABEL_STACK_O_ADJ,
        .label_stack_o_adj = {
            .adj = ai_mpls_10_10_11_1,
            .label_stack_size = 8,
            .label_stack = {
                200, 201, 202, 203, 204, 205, 206, 207
            },
            .eos = MPLS_EOS,
        },
    };
    fib_mpls_label_t *label_stack = NULL;
    vec_validate(label_stack, 7);
    for (ii = 0; ii < 8; ii++)
    {
	label_stack[ii].fml_value = ii + 200;
    }

    fei = fib_table_entry_update_one_path(fib_index,
                                          &pfx_2_2_5_5_s_32,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_11_1,
                                          tm->hw[1]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          label_stack,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ls_eos_o_10_10_10_1),
             "2.2.5.5/32 LB 1 buckets via: "
             "adj 10.10.11.1");
    fib_table_entry_delete_index(fei, FIB_SOURCE_API);

    /*
     * cleanup
     */
    fib_table_entry_delete(fib_index,
                           &pfx_1_1_1_2_s_32,
                           FIB_SOURCE_API);

    fei = fib_table_lookup(fib_index, &pfx_2_2_2_2_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l1600_eos_o_1_1_1_1),
             "2.2.2.2/32 LB 1 buckets via: "
             "label 1600 via 1.1,1.1");

    fib_table_entry_delete(fib_index,
                           &pfx_1_1_1_1_s_32,
                           FIB_SOURCE_API);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "2.2.2.2/32 LB 1 buckets via: DROP");

    fib_table_entry_delete(fib_index,
                           &pfx_2_2_2_2_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_2_2_2_3_s_32,
                           FIB_SOURCE_API);
    fib_table_entry_delete(fib_index,
                           &pfx_2_2_2_4_s_32,
                           FIB_SOURCE_API);

    adj_unlock(ai_mpls_10_10_10_1);
    adj_unlock(ai_mpls_10_10_11_2);
    adj_unlock(ai_v4_10_10_11_1);
    adj_unlock(ai_v4_10_10_11_2);
    adj_unlock(ai_mpls_10_10_11_1);

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    local0_pfx.fp_len = 32;
    fib_table_entry_delete(fib_index,
                           &local0_pfx,
                           FIB_SOURCE_INTERFACE);
    local0_pfx.fp_len = 24;
    fib_table_entry_delete(fib_index,
                           &local0_pfx,
                           FIB_SOURCE_INTERFACE);
    local1_pfx.fp_len = 32;
    fib_table_entry_delete(fib_index,
                           &local1_pfx,
                           FIB_SOURCE_INTERFACE);
    local1_pfx.fp_len = 24;
    fib_table_entry_delete(fib_index,
                           &local1_pfx,
                           FIB_SOURCE_INTERFACE);

    /*
     * +1 for the drop LB in the MPLS tables.
     */
    FIB_TEST(lb_count+1 == pool_elts(load_balance_pool),
             "Load-balance resources freed %d of %d",
             lb_count+1, pool_elts(load_balance_pool));

    return (res);
}

#define N_TEST_CHILDREN 4
#define PARENT_INDEX 0

typedef struct fib_node_test_t_
{
    fib_node_t node;
    u32 sibling;
    u32 index;
    fib_node_back_walk_ctx_t *ctxs;
    u32 destroyed;
} fib_node_test_t;

static fib_node_test_t fib_test_nodes[N_TEST_CHILDREN+1];

#define PARENT() (&fib_test_nodes[PARENT_INDEX].node)

#define FOR_EACH_TEST_CHILD(_tc)                \
    for (ii = 1, (_tc) = &fib_test_nodes[1];    \
         ii < N_TEST_CHILDREN+1;                \
         ii++, (_tc) = &fib_test_nodes[ii])

static fib_node_t *
fib_test_child_get_node (fib_node_index_t index)
{
    return (&fib_test_nodes[index].node);
}

static int fib_test_walk_spawns_walks;

static fib_node_back_walk_rc_t
fib_test_child_back_walk_notify (fib_node_t *node,
                                 fib_node_back_walk_ctx_t *ctx)
{
    fib_node_test_t *tc = (fib_node_test_t*) node;

    vec_add1(tc->ctxs, *ctx);

    if (1 == fib_test_walk_spawns_walks)
        fib_walk_sync(FIB_NODE_TYPE_TEST, tc->index, ctx);
    if (2 == fib_test_walk_spawns_walks)
        fib_walk_async(FIB_NODE_TYPE_TEST, tc->index,
                       FIB_WALK_PRIORITY_HIGH, ctx);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

static void
fib_test_child_last_lock_gone (fib_node_t *node)
{
    fib_node_test_t *tc = (fib_node_test_t *)node;

    tc->destroyed = 1;
}

/**
 * The FIB walk's graph node virtual function table
 */
static const fib_node_vft_t fib_test_child_vft = {
    .fnv_get = fib_test_child_get_node,
    .fnv_last_lock = fib_test_child_last_lock_gone,
    .fnv_back_walk = fib_test_child_back_walk_notify,
};

/*
 * the function (that should have been static but isn't so I can do this)
 * that processes the walk from the async queue,
 */
f64 fib_walk_process_queues(vlib_main_t * vm,
                            const f64 quota);
u32 fib_walk_queue_get_size(fib_walk_priority_t prio);

static int
fib_test_walk (void)
{
    fib_node_back_walk_ctx_t high_ctx = {}, low_ctx = {};
    fib_node_test_t *tc;
    vlib_main_t *vm;
    u32 ii, res;

    res = 0;
    vm = vlib_get_main();
    fib_node_register_type(FIB_NODE_TYPE_TEST, &fib_test_child_vft);

    /*
     * init a fake node on which we will add children
     */
    fib_node_init(&fib_test_nodes[PARENT_INDEX].node,
                  FIB_NODE_TYPE_TEST);

    FOR_EACH_TEST_CHILD(tc)
    {
        fib_node_init(&tc->node, FIB_NODE_TYPE_TEST);
        fib_node_lock(&tc->node);
        tc->ctxs = NULL;
        tc->index = ii;
        tc->sibling = fib_node_child_add(FIB_NODE_TYPE_TEST,
                                         PARENT_INDEX,
                                         FIB_NODE_TYPE_TEST, ii);
    }

    /*
     * enqueue a walk across the parents children.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    FIB_TEST(N_TEST_CHILDREN+1 == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children pre-walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * give the walk a large amount of time so it gets to the end
     */
    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        FIB_TEST(1 == vec_len(tc->ctxs),
                 "%d child visitsed %d times",
                 ii, vec_len(tc->ctxs));
        vec_free(tc->ctxs);
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is empty post walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * walk again. should be no increase in the number of visits, since
     * the walk will have terminated.
     */
    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        FIB_TEST(0 == vec_len(tc->ctxs),
                 "%d child visitsed %d times",
                 ii, vec_len(tc->ctxs));
    }

    /*
     * schedule a low and hig priority walk. expect the high to be performed
     * before the low.
     * schedule the high prio walk first so that it is further from the head
     * of the dependency list. that way it won't merge with the low one.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;
    low_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_LOW, &low_ctx);

    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        FIB_TEST(high_ctx.fnbw_reason == tc->ctxs[0].fnbw_reason,
                 "%d child visitsed by high prio walk", ii);
        FIB_TEST(low_ctx.fnbw_reason  == tc->ctxs[1].fnbw_reason,
                 "%d child visitsed by low prio walk", ii);
        vec_free(tc->ctxs);
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is empty post prio walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post prio walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * schedule 2 walks of the same priority that can be megred.
     * expect that each child is thus visited only once.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;
    low_ctx.fnbw_reason  = FIB_NODE_BW_REASON_FLAG_RESOLVE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &low_ctx);

    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        FIB_TEST(1 == vec_len(tc->ctxs),
                 "%d child visitsed %d times during merge walk",
                 ii, vec_len(tc->ctxs));
        vec_free(tc->ctxs);
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is empty post merge walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post merge walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * schedule 2 walks of the same priority that cannot be megred.
     * expect that each child is thus visited twice and in the order
     * in which the walks were scheduled.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;
    low_ctx.fnbw_reason  = FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &low_ctx);

    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        FIB_TEST(high_ctx.fnbw_reason == tc->ctxs[0].fnbw_reason,
                 "%d child visitsed by high prio walk", ii);
        FIB_TEST(low_ctx.fnbw_reason  == tc->ctxs[1].fnbw_reason,
                 "%d child visitsed by low prio walk", ii);
        vec_free(tc->ctxs);
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is empty post no-merge walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post no-merge walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * schedule a walk that makes one one child progress.
     * we do this by giving the queue draining process zero
     * time quanta. it's a do..while loop, so it does something.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    fib_walk_process_queues(vm, 0);

    FOR_EACH_TEST_CHILD(tc)
    {
        if (ii == N_TEST_CHILDREN)
        {
            FIB_TEST(1 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in zero quanta walk",
                     ii, vec_len(tc->ctxs));
        }
        else
        {
            FIB_TEST(0 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in 0 quanta walk",
                     ii, vec_len(tc->ctxs));
        }
    }
    FIB_TEST(1 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is not empty post zero quanta walk");
    FIB_TEST(N_TEST_CHILDREN+1 == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post zero qunta walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * another one step
     */
    fib_walk_process_queues(vm, 0);

    FOR_EACH_TEST_CHILD(tc)
    {
        if (ii >= N_TEST_CHILDREN-1)
        {
            FIB_TEST(1 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in 2nd zero quanta walk",
                     ii, vec_len(tc->ctxs));
        }
        else
        {
            FIB_TEST(0 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in 2nd 0 quanta walk",
                     ii, vec_len(tc->ctxs));
        }
    }
    FIB_TEST(1 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is not empty post zero quanta walk");
    FIB_TEST(N_TEST_CHILDREN+1 == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post zero qunta walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * schedule another walk that will catch-up and merge.
     */
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);
    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        if (ii >= N_TEST_CHILDREN-1)
        {
            FIB_TEST(2 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in 2nd zero quanta merge walk",
                     ii, vec_len(tc->ctxs));
            vec_free(tc->ctxs);
        }
        else
        {
            FIB_TEST(1 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in 2nd 0 quanta merge walk",
                     ii, vec_len(tc->ctxs));
            vec_free(tc->ctxs);
        }
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is not empty post 2nd zero quanta merge walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post 2nd zero qunta merge walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * park a async walk in the middle of the list, then have an sync walk catch
     * it. same expectations as async catches async.
     */
    high_ctx.fnbw_reason = FIB_NODE_BW_REASON_FLAG_RESOLVE;

    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);

    fib_walk_process_queues(vm, 0);
    fib_walk_process_queues(vm, 0);

    fib_walk_sync(FIB_NODE_TYPE_TEST, PARENT_INDEX, &high_ctx);

    FOR_EACH_TEST_CHILD(tc)
    {
        if (ii >= N_TEST_CHILDREN-1)
        {
            FIB_TEST(2 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in sync catches async walk",
                     ii, vec_len(tc->ctxs));
            vec_free(tc->ctxs);
        }
        else
        {
            FIB_TEST(1 == vec_len(tc->ctxs),
                     "%d child visitsed %d times in sync catches async walk",
                     ii, vec_len(tc->ctxs));
            vec_free(tc->ctxs);
        }
    }
    FIB_TEST(0 == fib_walk_queue_get_size(FIB_WALK_PRIORITY_HIGH),
             "Queue is not empty post 2nd zero quanta merge walk");
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post 2nd zero qunta merge walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * make the parent a child of one of its children, thus inducing a routing loop.
     */
    fib_test_nodes[PARENT_INDEX].sibling =
        fib_node_child_add(FIB_NODE_TYPE_TEST,
                           1, // the first child
                           FIB_NODE_TYPE_TEST,
                           PARENT_INDEX);

    /*
     * execute a sync walk from the parent. each child visited spawns more sync
     * walks. we expect the walk to terminate.
     */
    fib_test_walk_spawns_walks = 1;

    fib_walk_sync(FIB_NODE_TYPE_TEST, PARENT_INDEX, &high_ctx);

    FOR_EACH_TEST_CHILD(tc)
    {
        /*
         * child 1 - which is last in the list - has the loop.
         * the other children a re thus visitsed first. the we meet
         * child 1. we go round the loop again, visting the other children.
         * then we meet the walk in the dep list and bail. child 1 is not visitsed
         * again.
         */
        if (1 == ii)
        {
            FIB_TEST(1 == vec_len(tc->ctxs),
                     "child %d visitsed %d times during looped sync walk",
                     ii, vec_len(tc->ctxs));
        }
        else
        {
            FIB_TEST(2 == vec_len(tc->ctxs),
                     "child %d visitsed %d times during looped sync walk",
                     ii, vec_len(tc->ctxs));
        }
        vec_free(tc->ctxs);
    }
    FIB_TEST(N_TEST_CHILDREN == fib_node_list_get_size(PARENT()->fn_children),
             "Parent has %d children post sync loop walk",
             fib_node_list_get_size(PARENT()->fn_children));

    /*
     * the walk doesn't reach the max depth because the infra knows that sync
     * meets sync implies a loop and bails early.
     */
    FIB_TEST(high_ctx.fnbw_depth == 9,
             "Walk context depth %d post sync loop walk",
             high_ctx.fnbw_depth);

    /*
     * execute an async walk of the graph loop, with each child spawns sync walks
     */
    high_ctx.fnbw_depth = 0;
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);

    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        /*
         * we don't really care how many times the children are visited, as long as
         * it is more than once.
         */
        FIB_TEST(1 <= vec_len(tc->ctxs),
                 "child %d visitsed %d times during looped aync spawns sync walk",
                 ii, vec_len(tc->ctxs));
        vec_free(tc->ctxs);
    }

    /*
     * execute an async walk of the graph loop, with each child spawns async walks
     */
    fib_test_walk_spawns_walks = 2;
    high_ctx.fnbw_depth = 0;
    fib_walk_async(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                   FIB_WALK_PRIORITY_HIGH, &high_ctx);

    fib_walk_process_queues(vm, 1);

    FOR_EACH_TEST_CHILD(tc)
    {
        /*
         * we don't really care how many times the children are visited, as long as
         * it is more than once.
         */
        FIB_TEST(1 <= vec_len(tc->ctxs),
                 "child %d visitsed %d times during looped async spawns async walk",
                 ii, vec_len(tc->ctxs));
        vec_free(tc->ctxs);
    }


    fib_node_child_remove(FIB_NODE_TYPE_TEST,
                          1, // the first child
                          fib_test_nodes[PARENT_INDEX].sibling);

    /*
     * cleanup
     */
    FOR_EACH_TEST_CHILD(tc)
    {
        fib_node_child_remove(FIB_NODE_TYPE_TEST, PARENT_INDEX,
                              tc->sibling);
        fib_node_deinit(&tc->node);
        fib_node_unlock(&tc->node);
    }
    fib_node_deinit(PARENT());

    /*
     * The parent will be destroyed when the last lock on it goes.
     * this test ensures all the walk objects are unlocking it.
     */
    FIB_TEST((1 == fib_test_nodes[PARENT_INDEX].destroyed),
             "Parent was destroyed");

    return (res);
}

/*
 * declaration of the otherwise static callback functions
 */
void fib_bfd_notify (bfd_listen_event_e event,
                     const bfd_session_t *session);
void adj_bfd_notify (bfd_listen_event_e event,
                     const bfd_session_t *session);

/**
 * Test BFD session interaction with FIB
 */
static int
fib_test_bfd (void)
{
    fib_node_index_t fei;
    test_main_t *tm;
    int n_feis, res;

    res = 0;
    /* via 10.10.10.1 */
    ip46_address_t nh_10_10_10_1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
    };
    /* via 10.10.10.2 */
    ip46_address_t nh_10_10_10_2 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
    };
    /* via 10.10.10.10 */
    ip46_address_t nh_10_10_10_10 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a0a),
    };
    n_feis = fib_entry_pool_size();

    tm = &test_main;

    /*
     * add interface routes. we'll assume this works. it's tested elsewhere
     */
    fib_prefix_t pfx_10_10_10_10_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_10,
    };

    fib_table_entry_update_one_path(0, &pfx_10_10_10_10_s_24,
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

    fib_prefix_t pfx_10_10_10_10_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_10,
    };
    fib_table_entry_update_one_path(0, &pfx_10_10_10_10_s_32,
                                    FIB_SOURCE_INTERFACE,
                                    (FIB_ENTRY_FLAG_CONNECTED |
                                     FIB_ENTRY_FLAG_LOCAL),
                                    DPO_PROTO_IP4,
                                    NULL,
                                    tm->hw[0]->sw_if_index,
                                    ~0, // invalid fib index
                                    1, // weight
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * A BFD session via a neighbour we do not yet know
     */
    bfd_session_t bfd_10_10_10_1 = {
        .udp = {
            .key = {
                .fib_index = 0,
                .peer_addr = nh_10_10_10_1,
            },
        },
        .hop_type = BFD_HOP_TYPE_MULTI,
        .local_state = BFD_STATE_init,
    };

    fib_bfd_notify (BFD_LISTEN_EVENT_CREATE, &bfd_10_10_10_1);

    /*
     * A new entry will be created that forwards via the adj
     */
    adj_index_t ai_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                                    VNET_LINK_IP4,
                                                    &nh_10_10_10_1,
                                                    tm->hw[0]->sw_if_index);
    fib_prefix_t pfx_10_10_10_1_s_32 = {
        .fp_addr = nh_10_10_10_1,
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    };
    fib_test_lb_bucket_t adj_o_10_10_10_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_10_10_10_1,
        },
    };

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "BFD sourced %U via %U",
             format_fib_prefix, &pfx_10_10_10_1_s_32,
             format_ip_adjacency, ai_10_10_10_1, FORMAT_IP_ADJACENCY_NONE);

    /*
     * Delete the BFD session. Expect the fib_entry to be removed
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_DELETE, &bfd_10_10_10_1);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_1_s_32);
    FIB_TEST(FIB_NODE_INDEX_INVALID == fei,
             "BFD sourced %U removed",
             format_fib_prefix, &pfx_10_10_10_1_s_32);

    /*
     * Add the BFD source back
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_CREATE, &bfd_10_10_10_1);

    /*
     * source the entry via the ADJ fib
     */
    fei = fib_table_entry_path_add(0,
                                   &pfx_10_10_10_1_s_32,
                                   FIB_SOURCE_ADJ,
                                   FIB_ENTRY_FLAG_ATTACHED,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * Delete the BFD session. Expect the fib_entry to remain
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_DELETE, &bfd_10_10_10_1);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_1_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "BFD sourced %U remains via %U",
             format_fib_prefix, &pfx_10_10_10_1_s_32,
             format_ip_adjacency, ai_10_10_10_1, FORMAT_IP_ADJACENCY_NONE);

    /*
     * Add the BFD source back
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_CREATE, &bfd_10_10_10_1);

    /*
     * Create another ADJ FIB
     */
    fib_prefix_t pfx_10_10_10_2_s_32 = {
        .fp_addr = nh_10_10_10_2,
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    };
    fib_table_entry_path_add(0,
                             &pfx_10_10_10_2_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);
    /*
     * A BFD session for the new ADJ FIB
     */
    bfd_session_t bfd_10_10_10_2 = {
        .udp = {
            .key = {
                .fib_index = 0,
                .peer_addr = nh_10_10_10_2,
            },
        },
        .hop_type = BFD_HOP_TYPE_MULTI,
        .local_state = BFD_STATE_init,
    };

    fib_bfd_notify (BFD_LISTEN_EVENT_CREATE, &bfd_10_10_10_2);

    /*
     * remove the adj-fib source whilst the session is present
     * then add it back
     */
    fib_table_entry_delete(0, &pfx_10_10_10_2_s_32, FIB_SOURCE_ADJ);
    fib_table_entry_path_add(0,
                             &pfx_10_10_10_2_s_32,
                             FIB_SOURCE_ADJ,
                             FIB_ENTRY_FLAG_ATTACHED,
                             DPO_PROTO_IP4,
                             &nh_10_10_10_2,
                             tm->hw[0]->sw_if_index,
                             ~0, // invalid fib index
                             1,
                             NULL,
                             FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * Before adding a recursive via the BFD tracked ADJ-FIBs,
     * bring one of the sessions UP, leave the other down
     */
    bfd_10_10_10_1.local_state = BFD_STATE_up;
    fib_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_1);
    bfd_10_10_10_2.local_state = BFD_STATE_down;
    fib_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_2);

    /*
     * A recursive prefix via both of the ADJ FIBs
     */
    fib_prefix_t pfx_200_0_0_0_s_24 = {
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_len = 32,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0xc8000000),
        },
    };
    const dpo_id_t *dpo_10_10_10_1, *dpo_10_10_10_2;

    dpo_10_10_10_1 =
        fib_entry_contribute_ip_forwarding(
            fib_table_lookup_exact_match(0, &pfx_10_10_10_1_s_32));
    dpo_10_10_10_2 =
        fib_entry_contribute_ip_forwarding(
            fib_table_lookup_exact_match(0, &pfx_10_10_10_2_s_32));

    fib_test_lb_bucket_t lb_o_10_10_10_1 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = dpo_10_10_10_1->dpoi_index,
        },
    };
    fib_test_lb_bucket_t lb_o_10_10_10_2 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = dpo_10_10_10_2->dpoi_index,
        },
    };

    /*
     * A prefix via the adj-fib that is BFD down => DROP
     */
    fei = fib_table_entry_path_add(0,
                                   &pfx_200_0_0_0_s_24,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_2,
                                   ~0, // recursive
                                   0, // default fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * add a path via the UP BFD adj-fib.
     *  we expect that the DOWN BFD ADJ FIB is not used.
     */
    fei = fib_table_entry_path_add(0,
                                   &pfx_200_0_0_0_s_24,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   ~0, // recursive
                                   0, // default fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &lb_o_10_10_10_1),
             "Recursive %U only UP BFD adj-fibs",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * Send a BFD state change to UP - both sessions are now up
     *  the recursive prefix should LB over both
     */
    bfd_10_10_10_2.local_state = BFD_STATE_up;
    fib_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_2);


    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &lb_o_10_10_10_1,
                                      &lb_o_10_10_10_2),
             "Recursive %U via both UP BFD adj-fibs",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * Send a BFD state change to DOWN
     *  the recursive prefix should exclude the down
     */
    bfd_10_10_10_2.local_state = BFD_STATE_down;
    fib_bfd_notify (BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_2);


    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &lb_o_10_10_10_1),
             "Recursive %U via only UP",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * Delete the BFD session while it is in the DOWN state.
     *  FIB should consider the entry's state as back up
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_DELETE, &bfd_10_10_10_2);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &lb_o_10_10_10_1,
                                      &lb_o_10_10_10_2),
             "Recursive %U via both UP BFD adj-fibs post down session delete",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * Delete the BFD other session while it is in the UP state.
     */
    fib_bfd_notify (BFD_LISTEN_EVENT_DELETE, &bfd_10_10_10_1);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &lb_o_10_10_10_1,
                                      &lb_o_10_10_10_2),
             "Recursive %U via both UP BFD adj-fibs post up session delete",
             format_fib_prefix, &pfx_200_0_0_0_s_24);

    /*
     * cleaup
     */
    fib_table_entry_delete(0, &pfx_200_0_0_0_s_24, FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_10_10_10_1_s_32, FIB_SOURCE_ADJ);
    fib_table_entry_delete(0, &pfx_10_10_10_2_s_32, FIB_SOURCE_ADJ);

    fib_table_entry_delete(0, &pfx_10_10_10_10_s_32, FIB_SOURCE_INTERFACE);
    fib_table_entry_delete(0, &pfx_10_10_10_10_s_24, FIB_SOURCE_INTERFACE);

    adj_unlock(ai_10_10_10_1);
    /*
     * test no-one left behind
     */
    FIB_TEST((n_feis == fib_entry_pool_size()), "Entries gone");
    FIB_TEST(0 == adj_nbr_db_size(), "All adjacencies removed");

    /*
     * Single-hop BFD tests
     */
    bfd_10_10_10_1.hop_type = BFD_HOP_TYPE_SINGLE;
    bfd_10_10_10_1.udp.key.sw_if_index = tm->hw[0]->sw_if_index;

    adj_bfd_notify(BFD_LISTEN_EVENT_CREATE, &bfd_10_10_10_1);

    ai_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                        VNET_LINK_IP4,
                                        &nh_10_10_10_1,
                                        tm->hw[0]->sw_if_index);
    /*
     * whilst the BFD session is not signalled, the adj is up
     */
    FIB_TEST(!adj_is_up(ai_10_10_10_1), "Adj state down on uninit session");

    /*
     * bring the BFD session up
     */
    bfd_10_10_10_1.local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_1);
    FIB_TEST(adj_is_up(ai_10_10_10_1), "Adj state up on UP session");

    /*
     * bring the BFD session down
     */
    bfd_10_10_10_1.local_state = BFD_STATE_down;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_1);
    FIB_TEST(!adj_is_up(ai_10_10_10_1), "Adj state down on DOWN session");

    /*
     * add an attached next hop FIB entry via the down adj
     */
    fib_prefix_t pfx_5_5_5_5_s_32 = {
        .fp_addr = {
            .ip4 = {
                .as_u32 = clib_host_to_net_u32(0x05050505),
            },
        },
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    };

    fei = fib_table_entry_path_add(0,
                                   &pfx_5_5_5_5_s_32,
                                   FIB_SOURCE_CLI,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_1,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_5_5_5_5_s_32);

    /*
     * Add a path via an ADJ that is up
     */
    adj_index_t ai_10_10_10_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                                    VNET_LINK_IP4,
                                                    &nh_10_10_10_2,
                                                    tm->hw[0]->sw_if_index);

    fib_test_lb_bucket_t adj_o_10_10_10_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_10_10_10_2,
        },
    };
    adj_o_10_10_10_1.adj.adj = ai_10_10_10_1;

    fei = fib_table_entry_path_add(0,
                                   &pfx_5_5_5_5_s_32,
                                   FIB_SOURCE_CLI,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &nh_10_10_10_2,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "BFD sourced %U via %U",
             format_fib_prefix, &pfx_5_5_5_5_s_32,
             format_ip_adjacency, ai_10_10_10_2, FORMAT_IP_ADJACENCY_NONE);

    /*
     * Bring up the down session - should now LB
     */
    bfd_10_10_10_1.local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfd_10_10_10_1);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      2,
                                      &adj_o_10_10_10_1,
                                      &adj_o_10_10_10_2),
             "BFD sourced %U via noth adjs",
             format_fib_prefix, &pfx_5_5_5_5_s_32);

    /*
     * remove the BFD session state from the adj
     */
    adj_bfd_notify(BFD_LISTEN_EVENT_DELETE, &bfd_10_10_10_1);

    /*
     * clean-up
     */
    fib_table_entry_delete(0, &pfx_5_5_5_5_s_32, FIB_SOURCE_CLI);
    adj_unlock(ai_10_10_10_1);
    adj_unlock(ai_10_10_10_2);

    /*
     * test no-one left behind
     */
    FIB_TEST((n_feis == fib_entry_pool_size()), "Entries gone");
    FIB_TEST(0 == adj_nbr_db_size(), "All adjacencies removed");

    return (res);
}

static int
lfib_test (void)
{
    const mpls_label_t deag_label = 50;
    adj_index_t ai_mpls_10_10_10_1;
    dpo_id_t dpo = DPO_INVALID;
    const u32 lfib_index = 0;
    const u32 fib_index = 0;
    const dpo_id_t *dpo1;
    fib_node_index_t lfe;
    lookup_dpo_t *lkd;
    int lb_count, res;
    test_main_t *tm;

    res = 0;
    tm = &test_main;
    lb_count = pool_elts(load_balance_pool);

    FIB_TEST((0 == adj_nbr_db_size()), "ADJ DB size is %d",
             adj_nbr_db_size());

    /*
     * MPLS enable an interface so we get the MPLS table created
     */
    mpls_table_create(MPLS_FIB_DEFAULT_TABLE_ID, FIB_SOURCE_API, NULL);
    mpls_sw_interface_enable_disable(&mpls_main,
                                     tm->hw[0]->sw_if_index,
                                     1, 1);

    ip46_address_t nh_10_10_10_1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
    };
    ai_mpls_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                             VNET_LINK_MPLS,
                                             &nh_10_10_10_1,
                                             tm->hw[0]->sw_if_index);

    /*
     * Test the specials stack properly.
     */
    fib_prefix_t exp_null_v6_pfx = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_eos = MPLS_EOS,
        .fp_label = MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
        .fp_payload_proto = DPO_PROTO_IP6,
    };
    lfe = fib_table_lookup(lfib_index, &exp_null_v6_pfx);
    FIB_TEST((FIB_NODE_INDEX_INVALID != lfe),
             "%U/%U present",
             format_mpls_unicast_label, MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
             format_mpls_eos_bit, MPLS_EOS);
    fib_entry_contribute_forwarding(lfe,
                                    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                    &dpo);
    dpo1 = load_balance_get_bucket(dpo.dpoi_index, 0);
    lkd = lookup_dpo_get(dpo1->dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
             "%U/%U is deag in %d %U",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             lkd->lkd_fib_index,
             format_dpo_id, &dpo, 0);
    FIB_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
             "%U/%U is dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);
    FIB_TEST((LOOKUP_TABLE_FROM_INPUT_INTERFACE == lkd->lkd_table),
             "%U/%U is lookup in interface's table",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);
    FIB_TEST((DPO_PROTO_IP6 == lkd->lkd_proto),
             "%U/%U is %U dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             format_dpo_proto, lkd->lkd_proto);

    /*
     * A route deag route for EOS
     */
    fib_prefix_t pfx = {
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_eos = MPLS_EOS,
        .fp_label = deag_label,
        .fp_payload_proto = DPO_PROTO_IP4,
    };
    mpls_disp_dpo_t *mdd;
    lfe = fib_table_entry_path_add(lfib_index,
                                   &pfx,
                                   FIB_SOURCE_CLI,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &zero_addr,
                                   ~0,
                                   fib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((lfe == fib_table_lookup(lfib_index, &pfx)),
             "%U/%U present",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);

    fib_entry_contribute_forwarding(lfe,
                                    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                    &dpo);
    dpo1 = load_balance_get_bucket(dpo.dpoi_index, 0);
    mdd = mpls_disp_dpo_get(dpo1->dpoi_index);

    FIB_TEST((FIB_MPLS_LSP_MODE_PIPE == mdd->mdd_mode),
             "%U/%U disp is pipe mode",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);

    lkd = lookup_dpo_get(mdd->mdd_dpo.dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
             "%U/%U is deag in %d %U",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             lkd->lkd_fib_index,
             format_dpo_id, &dpo, 0);
    FIB_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
             "%U/%U is dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);
    FIB_TEST((DPO_PROTO_IP4 == lkd->lkd_proto),
             "%U/%U is %U dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             format_dpo_proto, lkd->lkd_proto);

    fib_table_entry_delete_index(lfe, FIB_SOURCE_CLI);

    FIB_TEST((FIB_NODE_INDEX_INVALID == fib_table_lookup(lfib_index,
							 &pfx)),
              "%U/%U not present",
              format_mpls_unicast_label, deag_label,
              format_mpls_eos_bit, MPLS_EOS);
    dpo_reset(&dpo);

    /*
     * A route deag route for EOS with LSP mode uniform
     */
    fib_mpls_label_t *l_pops = NULL, l_pop = {
        .fml_value = MPLS_LABEL_POP,
        .fml_mode = FIB_MPLS_LSP_MODE_UNIFORM,
    };
    vec_add1(l_pops, l_pop);
    lfe = fib_table_entry_path_add(lfib_index,
        			   &pfx,
        			   FIB_SOURCE_CLI,
        			   FIB_ENTRY_FLAG_NONE,
        			   DPO_PROTO_IP4,
        			   &zero_addr,
        			   ~0,
        			   fib_index,
        			   1,
        			   l_pops,
        			   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((lfe == fib_table_lookup(lfib_index, &pfx)),
              "%U/%U present",
              format_mpls_unicast_label, deag_label,
              format_mpls_eos_bit, MPLS_EOS);

    fib_entry_contribute_forwarding(lfe,
        			    FIB_FORW_CHAIN_TYPE_MPLS_EOS,
        			    &dpo);
    dpo1 = load_balance_get_bucket(dpo.dpoi_index, 0);
    mdd = mpls_disp_dpo_get(dpo1->dpoi_index);

    FIB_TEST((FIB_MPLS_LSP_MODE_UNIFORM == mdd->mdd_mode),
             "%U/%U disp is uniform mode",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);

    lkd = lookup_dpo_get(mdd->mdd_dpo.dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
              "%U/%U is deag in %d %U",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             lkd->lkd_fib_index,
             format_dpo_id, &dpo, 0);
    FIB_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
             "%U/%U is dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);
    FIB_TEST((DPO_PROTO_IP4 == lkd->lkd_proto),
             "%U/%U is %U dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS,
             format_dpo_proto, lkd->lkd_proto);

    fib_table_entry_delete_index(lfe, FIB_SOURCE_CLI);

    FIB_TEST((FIB_NODE_INDEX_INVALID == fib_table_lookup(lfib_index,
        						 &pfx)),
              "%U/%U not present",
              format_mpls_unicast_label, deag_label,
              format_mpls_eos_bit, MPLS_EOS);
    dpo_reset(&dpo);

    /*
     * A route deag route for non-EOS
     */
    pfx.fp_eos = MPLS_NON_EOS;
    lfe = fib_table_entry_path_add(lfib_index,
                                   &pfx,
                                   FIB_SOURCE_CLI,
                                   FIB_ENTRY_FLAG_NONE,
                                   DPO_PROTO_IP4,
                                   &zero_addr,
                                   ~0,
                                   lfib_index,
                                   1,
                                   NULL,
                                   FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST((lfe == fib_table_lookup(lfib_index, &pfx)),
             "%U/%U present",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_NON_EOS);

    fib_entry_contribute_forwarding(lfe,
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &dpo);
    dpo1 = load_balance_get_bucket(dpo.dpoi_index, 0);
    lkd = lookup_dpo_get(dpo1->dpoi_index);

    FIB_TEST((fib_index == lkd->lkd_fib_index),
             "%U/%U is deag in %d %U",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_NON_EOS,
             lkd->lkd_fib_index,
             format_dpo_id, &dpo, 0);
    FIB_TEST((LOOKUP_INPUT_DST_ADDR == lkd->lkd_input),
             "%U/%U is dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_NON_EOS);

    FIB_TEST((DPO_PROTO_MPLS == lkd->lkd_proto),
             "%U/%U is %U dst deag",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_NON_EOS,
             format_dpo_proto, lkd->lkd_proto);

    fib_table_entry_delete_index(lfe, FIB_SOURCE_CLI);

    FIB_TEST((FIB_NODE_INDEX_INVALID == fib_table_lookup(lfib_index,
                                                         &pfx)),
             "%U/%U not present",
             format_mpls_unicast_label, deag_label,
             format_mpls_eos_bit, MPLS_EOS);

    dpo_reset(&dpo);

    /*
     * An MPLS x-connect
     */
    fib_prefix_t pfx_1200 = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 1200,
        .fp_eos = MPLS_NON_EOS,
    };
    fib_test_lb_bucket_t neos_o_10_10_10_1 = {
        .type = FT_LB_LABEL_STACK_O_ADJ,
        .label_stack_o_adj = {
            .adj = ai_mpls_10_10_10_1,
            .label_stack_size = 4,
            .label_stack = {
                200, 300, 400, 500,
            },
            .eos = MPLS_NON_EOS,
        },
    };
    dpo_id_t neos_1200 = DPO_INVALID;
    dpo_id_t ip_1200 = DPO_INVALID;
    fib_mpls_label_t *l200 = NULL;
    u32 ii;
    for (ii = 0; ii < 4; ii++)
    {
        fib_mpls_label_t fml = {
            .fml_value = 200 + (ii * 100),
        };
        vec_add1(l200, fml);
    };

    lfe = fib_table_entry_update_one_path(fib_index,
                                          &pfx_1200,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          &nh_10_10_10_1,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          1,
                                          l200,
                                          FIB_ROUTE_PATH_FLAG_NONE);

    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &neos_o_10_10_10_1),
             "1200/0 LB 1 buckets via: "
             "adj 10.10.11.1");

    /*
     * A recursive route via the MPLS x-connect
     */
    fib_prefix_t pfx_2_2_2_3_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020203),
        },
    };
    fib_route_path_t *rpaths = NULL, rpath = {
        .frp_proto = DPO_PROTO_MPLS,
        .frp_local_label = 1200,
        .frp_eos = MPLS_NON_EOS,
        .frp_sw_if_index = ~0, // recurive
        .frp_fib_index = 0, // Default MPLS fib
        .frp_weight = 1,
        .frp_flags = FIB_ROUTE_PATH_FLAG_NONE,
        .frp_label_stack = NULL,
    };
    vec_add1(rpaths, rpath);

    fib_table_entry_path_add2(fib_index,
                              &pfx_2_2_2_3_s_32,
                              FIB_SOURCE_API,
                              FIB_ENTRY_FLAG_NONE,
                              rpaths);

    /*
     * A labelled recursive route via the MPLS x-connect
     */
    fib_prefix_t pfx_2_2_2_4_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = clib_host_to_net_u32(0x02020204),
        },
    };
    fib_mpls_label_t *l999 = NULL, fml_999 = {
        .fml_value = 999,
    };
    vec_add1(l999, fml_999);
    rpaths[0].frp_label_stack = l999,

        fib_table_entry_path_add2(fib_index,
                                  &pfx_2_2_2_4_s_32,
                                  FIB_SOURCE_API,
                                  FIB_ENTRY_FLAG_NONE,
                                  rpaths);

    fib_entry_contribute_forwarding(fib_table_lookup(fib_index, &pfx_1200),
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1200);
    fib_entry_contribute_forwarding(fib_table_lookup(fib_index, &pfx_1200),
                                    FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                    &neos_1200);

    fib_test_lb_bucket_t ip_o_1200 = {
        .type = FT_LB_O_LB,
        .lb = {
            .lb = ip_1200.dpoi_index,
        },
    };
    fib_test_lb_bucket_t mpls_o_1200 = {
        .type = FT_LB_LABEL_O_LB,
        .label_o_lb = {
            .lb = neos_1200.dpoi_index,
            .label = 999,
            .eos = MPLS_EOS,
        },
    };

    lfe = fib_table_lookup(fib_index, &pfx_2_2_2_3_s_32);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &ip_o_1200),
             "2.2.2.2.3/32 LB 1 buckets via: label 1200 EOS");
    lfe = fib_table_lookup(fib_index, &pfx_2_2_2_4_s_32);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &mpls_o_1200),
             "2.2.2.2.4/32 LB 1 buckets via: label 1200 non-EOS");

    fib_table_entry_delete(fib_index, &pfx_1200, FIB_SOURCE_API);
    fib_table_entry_delete(fib_index, &pfx_2_2_2_3_s_32, FIB_SOURCE_API);
    fib_table_entry_delete(fib_index, &pfx_2_2_2_4_s_32, FIB_SOURCE_API);

    dpo_reset(&neos_1200);
    dpo_reset(&ip_1200);

    /*
     * A recursive via a label that does not exist
     */
    fib_test_lb_bucket_t bucket_drop = {
        .type = FT_LB_DROP,
        .special = {
            .adj = DPO_PROTO_IP4,
        },
    };
    fib_test_lb_bucket_t mpls_bucket_drop = {
        .type = FT_LB_DROP,
        .special = {
            .adj = DPO_PROTO_MPLS,
        },
    };

    rpaths[0].frp_label_stack = NULL;
    lfe = fib_table_entry_path_add2(fib_index,
                                    &pfx_2_2_2_4_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    rpaths);

    fib_entry_contribute_forwarding(fib_table_lookup(fib_index, &pfx_1200),
                                    FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                    &ip_1200);
    ip_o_1200.lb.lb = ip_1200.dpoi_index;

    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "2.2.2.2.4/32 LB 1 buckets via: drop");
    lfe = fib_table_lookup(fib_index, &pfx_1200);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "1200/neos LB 1 buckets via: ip4-DROP");
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS,
                                      1,
                                      &mpls_bucket_drop),
             "1200/neos LB 1 buckets via: mpls-DROP");

    fib_table_entry_delete(fib_index, &pfx_2_2_2_4_s_32, FIB_SOURCE_API);

    dpo_reset(&ip_1200);

    /*
     * An rx-interface route.
     *  like the tail of an mcast LSP
     */
    dpo_id_t idpo = DPO_INVALID;

    interface_rx_dpo_add_or_lock(DPO_PROTO_IP4,
                                 tm->hw[0]->sw_if_index,
                                 &idpo);

    fib_prefix_t pfx_2500 = {
        .fp_len = 21,
        .fp_proto = FIB_PROTOCOL_MPLS,
        .fp_label = 2500,
        .fp_eos = MPLS_EOS,
        .fp_payload_proto = DPO_PROTO_IP4,
    };
    fib_test_lb_bucket_t rx_intf_0 = {
        .type = FT_LB_INTF,
        .adj = {
            .adj = idpo.dpoi_index,
        },
    };

    lfe = fib_table_entry_update_one_path(fib_index,
                                          &pfx_2500,
                                          FIB_SOURCE_API,
                                          FIB_ENTRY_FLAG_NONE,
                                          DPO_PROTO_IP4,
                                          NULL,
                                          tm->hw[0]->sw_if_index,
                                          ~0, // invalid fib index
                                          0,
                                          NULL,
                                          FIB_ROUTE_PATH_INTF_RX);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      1,
                                      &rx_intf_0),
             "2500 rx-interface 0");
    fib_table_entry_delete(fib_index, &pfx_2500, FIB_SOURCE_API);

    /*
     * An MPLS mulicast entry
     */
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
    fib_test_rep_bucket_t mc_intf_0 = {
        .type = FT_REP_INTF,
        .adj = {
            .adj = idpo.dpoi_index,
        },
    };
    fib_mpls_label_t *l3300 = NULL, fml_3300 = {
        .fml_value = 3300,
    };
    vec_add1(l3300, fml_3300);

    lfe = fib_table_entry_update_one_path(lfib_index,
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
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      1,
                                      &mc_0),
             "3500 via replicate over 10.10.10.1");

    /*
     * MPLS Bud-node. Add a replication via an interface-receieve path
     */
    lfe = fib_table_entry_path_add(lfib_index,
                                   &pfx_3500,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_MULTICAST,
                                   DPO_PROTO_IP4,
                                   NULL,
                                   tm->hw[0]->sw_if_index,
                                   ~0, // invalid fib index
                                   0,
                                   NULL,
                                   FIB_ROUTE_PATH_INTF_RX);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      2,
                                      &mc_0,
                                      &mc_intf_0),
             "3500 via replicate over 10.10.10.1 and interface-rx");

    /*
     * Add a replication via an interface-free for-us path
     */
    fib_test_rep_bucket_t mc_disp = {
        .type = FT_REP_DISP_MFIB_LOOKUP,
        .adj = {
            .adj = idpo.dpoi_index,
        },
    };
    lfe = fib_table_entry_path_add(lfib_index,
                                   &pfx_3500,
                                   FIB_SOURCE_API,
                                   FIB_ENTRY_FLAG_MULTICAST,
                                   DPO_PROTO_IP4,
                                   NULL,
                                   5, // rpf-id
                                   0, // default table
                                   0,
                                   NULL,
                                   FIB_ROUTE_PATH_RPF_ID);
    FIB_TEST(!fib_test_validate_entry(lfe,
                                      FIB_FORW_CHAIN_TYPE_MPLS_EOS,
                                      3,
                                      &mc_0,
                                      &mc_disp,
                                      &mc_intf_0),
             "3500 via replicate over 10.10.10.1 and interface-rx");



    fib_table_entry_delete(fib_index, &pfx_3500, FIB_SOURCE_API);
    dpo_reset(&idpo);

    /*
     * cleanup
     */
    mpls_sw_interface_enable_disable(&mpls_main,
                                     tm->hw[0]->sw_if_index,
                                     0, 1);
    mpls_table_delete(MPLS_FIB_DEFAULT_TABLE_ID, FIB_SOURCE_API);

    FIB_TEST(0 == pool_elts(mpls_disp_dpo_pool),
	     "mpls_disp_dpo resources freed %d of %d",
             0, pool_elts(mpls_disp_dpo_pool));
    FIB_TEST(lb_count == pool_elts(load_balance_pool),
             "Load-balance resources freed %d of %d",
             lb_count, pool_elts(load_balance_pool));
    FIB_TEST(0 == pool_elts(interface_rx_dpo_pool),
             "interface_rx_dpo resources freed %d of %d",
             0, pool_elts(interface_rx_dpo_pool));

    return (res);
}

static int
fib_test_inherit (void)
{
    fib_node_index_t fei;
    test_main_t *tm;
    int n_feis, res;

    res = 0;
    n_feis = fib_entry_pool_size();
    tm = &test_main;

    const ip46_address_t nh_10_10_10_1 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a01),
    };
    const ip46_address_t nh_10_10_10_2 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02),
    };
    const ip46_address_t nh_10_10_10_3 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a03),
    };
    const ip46_address_t nh_10_10_10_16 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a10),
    };
    const ip46_address_t nh_10_10_10_20 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a14),
    };
    const ip46_address_t nh_10_10_10_21 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a15),
    };
    const ip46_address_t nh_10_10_10_22 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a16),
    };
    const ip46_address_t nh_10_10_10_255 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0aff),
    };
    const ip46_address_t nh_10_10_10_0 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a00),
    };
    const ip46_address_t nh_10_10_0_0 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0000),
    };
    const ip46_address_t nh_11_11_11_11 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0b0b0b0b),
    };
    const ip46_address_t nh_11_11_11_0 = {
        .ip4.as_u32 = clib_host_to_net_u32(0x0b0b0b00),
    };

    /*
     * prefixes at the base of a sub-tree
     */
    const fib_prefix_t pfx_10_10_10_21_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_21,
    };
    const fib_prefix_t pfx_10_10_10_22_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_22,
    };
    const fib_prefix_t pfx_10_10_10_255_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_255,
    };
    const u32 N_PLS = fib_path_list_pool_size();

    fib_table_entry_special_add(0,
                                &pfx_10_10_10_21_s_32,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);
    fib_table_entry_special_add(0,
                                &pfx_10_10_10_22_s_32,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);
    fib_table_entry_special_add(0,
                                &pfx_10_10_10_255_s_32,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);

    /*
     * source an entry that pushes its state down the sub-tree
     */
    const fib_prefix_t pfx_10_10_10_16_s_28 = {
        .fp_len = 28,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_16,
    };
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_16_s_28,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * this covering entry and all those below it should have
     * the same forwarding information.
     */
    adj_index_t ai_10_10_10_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                                    VNET_LINK_IP4,
                                                    &nh_10_10_10_1,
                                                    tm->hw[0]->sw_if_index);
    fib_test_lb_bucket_t adj_o_10_10_10_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_10_10_10_1,
        },
    };

    fei = fib_table_lookup(0, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_16_s_28);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_255_s_32);

    /*
     * remove the inherting cover - covereds go back to drop
     */
    fib_table_entry_delete(0, &pfx_10_10_10_16_s_28, FIB_SOURCE_API);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_21_s_32);

    /*
     * source an entry that pushes its state down the sub-tree
     */
    const fib_prefix_t pfx_10_10_10_0_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_0,
    };
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_0_s_24,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    /*
     * whole sub-tree now covered
     */
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_0_s_24);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_255_s_32);

    /*
     * insert a more specific into the sub-tree - expect inheritance
     *  this one is directly covered by the root
     */
    fib_table_entry_special_add(0,
                                &pfx_10_10_10_16_s_28,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_16_s_28);

    /*
     * insert a more specific into the sub-tree - expect inheritance
     *  this one is indirectly covered by the root
     */
    const fib_prefix_t pfx_10_10_10_20_s_30 = {
        .fp_len = 30,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_10_20,
    };
    fib_table_entry_special_add(0,
                                &pfx_10_10_10_20_s_30,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_20_s_30);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_20_s_30);

    /*
     * remove the prefix from the middle of the sub-tree
     *  the inherited source will be the only one remaining - expect
     *  it to be withdrawn and hence the prefix is removed.
     */
    fib_table_entry_special_remove(0,
                                   &pfx_10_10_10_20_s_30,
                                   FIB_SOURCE_CLI);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_20_s_30);
    FIB_TEST((FIB_NODE_INDEX_INVALID == fei),
             "%U gone",
             format_fib_prefix, &pfx_10_10_10_20_s_30);

    /*
     * inheriting source is modifed - expect the modification to be present
     *  throughout the sub-tree
     */
    adj_index_t ai_10_10_10_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                                    VNET_LINK_IP4,
                                                    &nh_10_10_10_2,
                                                    tm->hw[0]->sw_if_index);
    fib_test_lb_bucket_t adj_o_10_10_10_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_10_10_10_2,
        },
    };

    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_0_s_24,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_2,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_0_s_24);

    fib_source_t hi_src = fib_source_allocate("test", 0x50,
                                              FIB_SOURCE_BH_SIMPLE);

    /*
     * add the source that replaces inherited state.
     * inheriting source is not the best, so it doesn't push state.
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_0_s_24,
                                    hi_src,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_0_s_24);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_16_s_28);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_10_10_10_16_s_28);

    /*
     * withdraw the higher priority source and expect the inherited to return
     * throughout the sub-tree
     */
    fib_table_entry_delete(0, &pfx_10_10_10_0_s_24, hi_src);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_0_s_24);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_16_s_28);

    /*
     * source a covered entry in the sub-tree with the same inherting source
     *  - expect that it now owns the sub-tree and thus over-rides its cover
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_16_s_28,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_16_s_28);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_21_s_32);

    /* these two unaffected by the sub-tree change */
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_0_s_24);

    /*
     * removes the more specific, expect the /24 to now re-owns the sub-tree
     */
    fib_table_entry_delete(0, &pfx_10_10_10_16_s_28, FIB_SOURCE_API);

    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_10_0_s_24);
    /*
     * modify the /24. expect the new forwarding to be pushed down
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_0_s_24,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_16_s_28);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_21_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_0_s_24);

    /*
     * add an entry less specific to /24. it should not own the /24's tree
     */
    const fib_prefix_t pfx_10_10_0_0_s_16 = {
        .fp_len = 16,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_10_10_0_0,
    };
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_0_0_s_16,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_2,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_16_s_28);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_22_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_22_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_255_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_255_s_32);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_1),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_0_s_24);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_0_0_s_16);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_2),
             "%U via 10.10.10.2",
             format_fib_prefix, &pfx_10_10_0_0_s_16);

    /*
     * Add/remove an interposer source to a new /32
     */
    const fib_prefix_t pfx_11_11_11_11_s_32 = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_11_11_11_11,
    };

    fib_table_entry_update_one_path(0,
                                    &pfx_11_11_11_11_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_3,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    dpo_id_t interposer = DPO_INVALID;
    fib_mpls_label_t *l99 = NULL, fml_99 = {
        .fml_value = 99,
    };
    vec_add1(l99, fml_99);

    mpls_label_dpo_create(l99,
                          MPLS_EOS,
                          DPO_PROTO_IP4,
                          MPLS_LABEL_DPO_FLAG_NONE,
                          punt_dpo_get(DPO_PROTO_MPLS),
                          &interposer);

    adj_index_t ai_10_10_10_3 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                                    VNET_LINK_IP4,
                                                    &nh_10_10_10_3,
                                                    tm->hw[0]->sw_if_index);
    fib_test_lb_bucket_t adj_o_10_10_10_3 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_10_10_10_3,
        },
    };
    fib_test_lb_bucket_t l99_o_10_10_10_3 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .adj = ai_10_10_10_3,
            .label = 99,
            .eos = MPLS_EOS,
        },
    };

    fei = fib_table_entry_special_dpo_add(0,
                                          &pfx_11_11_11_11_s_32,
                                          FIB_SOURCE_SPECIAL,
                                          FIB_ENTRY_FLAG_INTERPOSE,
                                          &interposer);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer adj",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    fib_table_entry_special_remove(0,
                                   &pfx_11_11_11_11_s_32,
                                   FIB_SOURCE_SPECIAL);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_3),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_11_11_11_11_s_32);

    /*
     * remove and re-add the second best API source while the interpose
     * is present
     */
    fei = fib_table_entry_special_dpo_add(0,
                                          &pfx_11_11_11_11_s_32,
                                          FIB_SOURCE_SPECIAL,
                                          FIB_ENTRY_FLAG_INTERPOSE,
                                          &interposer);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer adj",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    FIB_TEST(2 == pool_elts(mpls_label_dpo_pool),
             "MPLS label pool: %d",
             pool_elts(mpls_label_dpo_pool));

    fib_table_entry_delete(0, &pfx_11_11_11_11_s_32, FIB_SOURCE_API);

    /*
     * the interpose does not get stacked when there are not valid paths
     */
    fib_test_lb_bucket_t bucket_drop = {
        .type = FT_LB_DROP,
        .special = {
            .adj = DPO_PROTO_IP4,
        },
    };
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "%U via drop",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    fib_table_entry_update_one_path(0,
                                    &pfx_11_11_11_11_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_3,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer adj",
             format_fib_prefix,&pfx_11_11_11_11_s_32);
    fib_table_entry_delete(0, &pfx_11_11_11_11_s_32, FIB_SOURCE_API);

    /*
     * add a cover for the interposed entry, so that we test it selects
     * the covers forwarding.
     */
    const fib_prefix_t pfx_11_11_11_0_s_24 = {
        .fp_len = 24,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = nh_11_11_11_0,
    };
    fib_table_entry_update_one_path(0,
                                    &pfx_11_11_11_0_s_24,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_3,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer adj",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    /*
     * multiple interpose sources on the same entry. Only the high
     * priority source gets to add the interpose.
     */
    dpo_id_t interposer2 = DPO_INVALID;
    fib_mpls_label_t *l100 = NULL, fml_100 = {
        .fml_value = 100,
    };
    vec_add1(l100, fml_100);

    mpls_label_dpo_create(l100,
                          MPLS_EOS,
                          DPO_PROTO_IP4,
                          MPLS_LABEL_DPO_FLAG_NONE,
                          punt_dpo_get(DPO_PROTO_MPLS),
                          &interposer2);

    fei = fib_table_entry_special_dpo_add(0,
                                          &pfx_11_11_11_11_s_32,
                                          FIB_SOURCE_CLASSIFY,
                                          FIB_ENTRY_FLAG_INTERPOSE,
                                          &interposer2);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer label 99",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    fib_test_lb_bucket_t l100_o_10_10_10_3 = {
        .type = FT_LB_LABEL_O_ADJ,
        .label_o_adj = {
            .adj = ai_10_10_10_3,
            .label = 100,
            .eos = MPLS_EOS,
        },
    };

    fib_table_entry_delete(0, &pfx_11_11_11_11_s_32, FIB_SOURCE_SPECIAL);

    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l100_o_10_10_10_3),
             "%U via interposer label 99",
             format_fib_prefix,&pfx_11_11_11_11_s_32);

    fib_table_entry_delete(0, &pfx_11_11_11_0_s_24, FIB_SOURCE_API);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "%U via drop",
             format_fib_prefix,&pfx_11_11_11_11_s_32);
    fib_table_entry_delete(0, &pfx_11_11_11_11_s_32, FIB_SOURCE_CLASSIFY);

    /*
     * update a source to/from interpose.
     */
    /* fib_table_entry_update_one_path(0, */
    /*                                 &pfx_11_11_11_0_s_24, */
    /*                              FIB_SOURCE_API, */
    /*                              FIB_ENTRY_FLAG_NONE, */
    /*                              DPO_PROTO_IP4, */
    /*                                 &nh_10_10_10_3, */
    /*                              tm->hw[0]->sw_if_index, */
    /*                              ~0, */
    /*                              1, */
    /*                              NULL, */
    /*                              FIB_ROUTE_PATH_FLAG_NONE); */
    /* fei = fib_table_entry_special_dpo_add(0, */
    /*                                       &pfx_11_11_11_11_s_32, */
    /*                                       FIB_SOURCE_API, */
    /*                                       FIB_ENTRY_FLAG_INTERPOSE, */
    /*                                       &interposer); */
    /* FIB_TEST(!fib_test_validate_entry(fei, */
    /*                                   FIB_FORW_CHAIN_TYPE_UNICAST_IP4, */
    /*                                   1, */
    /*                                   &l99_o_10_10_10_3), */
    /*          "%U via interposer label 99", */
    /*          format_fib_prefix,&pfx_11_11_11_11_s_32); */

    /* FIB_TEST(3 == pool_elts(mpls_label_dpo_pool), */
    /*          "MPLS label pool: %d", */
    /*          pool_elts(mpls_label_dpo_pool)); */
    /* FIB_TEST((2 == mpls_label_dpo_get(interposer.dpoi_index)->mld_locks), */
    /*          "Interposer %d locks", */
    /*          mpls_label_dpo_get(interposer.dpoi_index)->mld_locks); */

    /* fib_table_entry_update_one_path(0, */
    /*                                 &pfx_11_11_11_11_s_32, */
    /*                              FIB_SOURCE_API, */
    /*                              FIB_ENTRY_FLAG_NONE, */
    /*                              DPO_PROTO_IP4, */
    /*                                 &nh_10_10_10_2, */
    /*                              tm->hw[0]->sw_if_index, */
    /*                              ~0, */
    /*                              1, */
    /*                              NULL, */
    /*                              FIB_ROUTE_PATH_FLAG_NONE); */
    /* FIB_TEST(!fib_test_validate_entry(fei, */
    /*                                   FIB_FORW_CHAIN_TYPE_UNICAST_IP4, */
    /*                                   1, */
    /*                                   &adj_o_10_10_10_2), */
    /*          "%U via 10.10.10.2", */
    /*          format_fib_prefix,&pfx_11_11_11_11_s_32); */

    /* FIB_TEST((1 == mpls_label_dpo_get(interposer.dpoi_index)->mld_locks), */
    /*          "Interposer %d locks", */
    /*          mpls_label_dpo_get(interposer.dpoi_index)->mld_locks); */
    /* FIB_TEST(2 == pool_elts(mpls_label_dpo_pool), */
    /*          "MPLS label pool: %d", */
    /*          pool_elts(mpls_label_dpo_pool)); */

    /* fei = fib_table_entry_special_dpo_add(0, */
    /*                                       &pfx_11_11_11_11_s_32, */
    /*                                       FIB_SOURCE_API, */
    /*                                       FIB_ENTRY_FLAG_INTERPOSE, */
    /*                                       &interposer); */
    /* FIB_TEST(!fib_test_validate_entry(fei, */
    /*                                   FIB_FORW_CHAIN_TYPE_UNICAST_IP4, */
    /*                                   1, */
    /*                                   &l99_o_10_10_10_3), */
    /*          "%U via interposer label 99", */
    /*          format_fib_prefix,&pfx_11_11_11_11_s_32); */

    /* fib_table_entry_delete(0, &pfx_11_11_11_11_s_32, FIB_SOURCE_API); */

    /*
     * Add/remove an interposer source from the top of the subtrie. The
     * interposer source is not inherited.
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_0_s_24,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_3,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_entry_special_dpo_add(0,
                                          &pfx_10_10_10_0_s_24,
                                          FIB_SOURCE_SPECIAL,
                                          FIB_ENTRY_FLAG_INTERPOSE,
                                          &interposer);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer label",
             format_fib_prefix,&pfx_10_10_10_0_s_24);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "%U via drop",
             format_fib_prefix, &pfx_10_10_10_21_s_32);

    fib_table_entry_special_remove(0,
                                   &pfx_10_10_10_0_s_24,
                                   FIB_SOURCE_SPECIAL);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_0_s_24);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_3),
             "%U via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_0_s_24);
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &adj_o_10_10_10_3),
             "%U via via 10.10.10.1",
             format_fib_prefix, &pfx_10_10_10_21_s_32);

    /*
     * Add/remove an interposer source from the top of the subtrie. The
     * interposer source is inherited.
     */
    fei = fib_table_entry_special_dpo_add(0,
                                          &pfx_10_10_10_0_s_24,
                                          FIB_SOURCE_SPECIAL,
                                          (FIB_ENTRY_FLAG_COVERED_INHERIT |
                                           FIB_ENTRY_FLAG_INTERPOSE),
                                          &interposer);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer label",
             format_fib_prefix,&pfx_10_10_10_0_s_24);

    /* interposer gets forwarding from the drop cli source */
    fei = fib_table_lookup_exact_match(0, &pfx_10_10_10_21_s_32);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &bucket_drop),
             "%U via drop",
             format_fib_prefix,&pfx_10_10_10_21_s_32);

    fib_table_entry_update_one_path(0,
                                    &pfx_10_10_10_21_s_32,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_NONE,
                                    DPO_PROTO_IP4,
                                    &nh_10_10_10_3,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fib_table_entry_delete(0, &pfx_10_10_10_21_s_32, FIB_SOURCE_CLI);
    /* interposer gets forwarding from the API source */
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                      1,
                                      &l99_o_10_10_10_3),
             "%U via interposer label",
             format_fib_prefix,&pfx_10_10_10_21_s_32);

    /*
     * cleanup
     */
    fib_table_entry_delete(0, &pfx_10_10_10_22_s_32, FIB_SOURCE_CLI);
    fib_table_entry_delete(0, &pfx_10_10_10_21_s_32, FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_10_10_10_16_s_28, FIB_SOURCE_CLI);
    fib_table_entry_delete(0, &pfx_10_10_10_255_s_32, FIB_SOURCE_CLI);
    fib_table_entry_delete(0, &pfx_10_10_10_0_s_24, FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_10_10_0_0_s_16, FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_10_10_10_0_s_24, FIB_SOURCE_SPECIAL);
    adj_unlock(ai_10_10_10_1);
    adj_unlock(ai_10_10_10_2);
    adj_unlock(ai_10_10_10_3);
    dpo_reset(&interposer);
    dpo_reset(&interposer2);
    FIB_TEST(0 == pool_elts(mpls_label_dpo_pool),
             "MPLS label pool empty: %d",
             pool_elts(mpls_label_dpo_pool));
    FIB_TEST(0 == adj_nbr_db_size(), "All adjacencies removed");
    FIB_TEST(N_PLS == fib_path_list_pool_size(),
             "number of path-lists: %d = %d",
             N_PLS, fib_path_list_pool_size());

    /*
     * test the v6 tree walk.
     * a /64 that covers everything. a /96 that covers one /128
     * a second /128 covered only by the /64.
     */
    const fib_prefix_t pfx_2001_s_64 = {
        .fp_len = 64,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000000),
                    [1] = clib_host_to_net_u64(0x0000000000000000),
                },
            },
        },
    };
    const fib_prefix_t pfx_2001_1_s_96 = {
        .fp_len = 96,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000000),
                    [1] = clib_host_to_net_u64(0x1000000000000000),
                },
            },
        },
    };
    const fib_prefix_t pfx_2001_1_1_s_128 = {
        .fp_len = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000000),
                    [1] = clib_host_to_net_u64(0x1000000000000001),
                },
            },
        },
    };
    const fib_prefix_t pfx_2001_0_1_s_128 = {
        .fp_len = 128,
        .fp_proto = FIB_PROTOCOL_IP6,
        .fp_addr = {
            .ip6 = {
                .as_u64 = {
                    [0] = clib_host_to_net_u64(0x2001000000000000),
                    [1] = clib_host_to_net_u64(0x0000000000000001),
                },
            },
        },
    };
    const ip46_address_t nh_3000_1 = {
        .ip6 = {
            .as_u64 = {
                [0] = clib_host_to_net_u64(0x3000000000000000),
                [1] = clib_host_to_net_u64(0x0000000000000001),
            },
        },
    };
    const ip46_address_t nh_3000_2 = {
        .ip6 = {
            .as_u64 = {
                [0] = clib_host_to_net_u64(0x3000000000000000),
                [1] = clib_host_to_net_u64(0x0000000000000002),
            },
        },
    };
    adj_index_t ai_3000_1 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP6,
                                                VNET_LINK_IP6,
                                                &nh_3000_1,
                                                tm->hw[0]->sw_if_index);
    adj_index_t ai_3000_2 = adj_nbr_add_or_lock(FIB_PROTOCOL_IP6,
                                                VNET_LINK_IP6,
                                                &nh_3000_2,
                                                tm->hw[0]->sw_if_index);
    fib_test_lb_bucket_t adj_o_3000_1 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_3000_1,
        },
    };
    fib_test_lb_bucket_t adj_o_3000_2 = {
        .type = FT_LB_ADJ,
        .adj = {
            .adj = ai_3000_2,
        },
    };

    fib_table_entry_special_add(0,
                                &pfx_2001_0_1_s_128,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);
    fib_table_entry_special_add(0,
                                &pfx_2001_1_1_s_128,
                                FIB_SOURCE_CLI,
                                FIB_ENTRY_FLAG_DROP);

    /*
     * /96 has inherited forwarding pushed down to its covered /128
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_2001_1_s_96,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP6,
                                    &nh_3000_1,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);
    fei = fib_table_lookup_exact_match(0, &pfx_2001_1_s_96);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_1),
             "%U via 3000::1",
             format_fib_prefix, &pfx_2001_1_s_96);
    fei = fib_table_lookup_exact_match(0, &pfx_2001_1_1_s_128);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_1),
             "%U via 3000::1",
             format_fib_prefix, &pfx_2001_1_1_s_128);
    fei = fib_table_lookup_exact_match(0, &pfx_2001_0_1_s_128);
    FIB_TEST(load_balance_is_drop(fib_entry_contribute_ip_forwarding(fei)),
             "%U resolves via drop",
             format_fib_prefix, &pfx_2001_0_1_s_128);

    /*
     * /64 has inherited forwarding pushed down to all, but the /96
     * and its sub-tree remain unaffected.
     */
    fib_table_entry_update_one_path(0,
                                    &pfx_2001_s_64,
                                    FIB_SOURCE_API,
                                    FIB_ENTRY_FLAG_COVERED_INHERIT,
                                    DPO_PROTO_IP6,
                                    &nh_3000_2,
                                    tm->hw[0]->sw_if_index,
                                    ~0,
                                    1,
                                    NULL,
                                    FIB_ROUTE_PATH_FLAG_NONE);

    fei = fib_table_lookup_exact_match(0, &pfx_2001_s_64);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_2),
             "%U via 3000::2",
             format_fib_prefix, &pfx_2001_s_64);
    fei = fib_table_lookup_exact_match(0, &pfx_2001_0_1_s_128);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_2),
             "%U via 3000::1",
             format_fib_prefix, &pfx_2001_0_1_s_128);

    fei = fib_table_lookup_exact_match(0, &pfx_2001_1_s_96);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_1),
             "%U via 3000::1",
             format_fib_prefix, &pfx_2001_1_s_96);
    fei = fib_table_lookup_exact_match(0, &pfx_2001_1_1_s_128);
    FIB_TEST(!fib_test_validate_entry(fei,
                                      FIB_FORW_CHAIN_TYPE_UNICAST_IP6,
                                      1,
                                      &adj_o_3000_1),
             "%U via 3000::1",
             format_fib_prefix, &pfx_2001_1_1_s_128);

    /*
     * Cleanup
     */
    fib_table_entry_delete(0, &pfx_2001_0_1_s_128, FIB_SOURCE_CLI);
    fib_table_entry_delete(0, &pfx_2001_1_1_s_128, FIB_SOURCE_CLI);
    fib_table_entry_delete(0, &pfx_2001_s_64,      FIB_SOURCE_API);
    fib_table_entry_delete(0, &pfx_2001_1_s_96,    FIB_SOURCE_API);
    adj_unlock(ai_3000_1);
    adj_unlock(ai_3000_2);

    /*
     * test no-one left behind
     */
    FIB_TEST((n_feis == fib_entry_pool_size()), "Entries gone");
    FIB_TEST(0 == adj_nbr_db_size(), "All adjacencies removed");

    return (res);
}

static int
fib_test_sticky (void)
{
    fib_route_path_t *r_paths = NULL;
    test_main_t *tm = &test_main;
    u32 ii, lb_count, pl_count;
    dpo_id_t dpo = DPO_INVALID;
    fib_node_index_t pl_index;
    int res = 0;
#define N_PATHS 16

    fib_test_lb_bucket_t buckets[N_PATHS];
    bfd_session_t bfds[N_PATHS] = {{0}};

    lb_count = pool_elts(load_balance_pool);
    pl_count = fib_path_list_pool_size();

    for (ii = 0; ii < N_PATHS; ii++)
    {
        ip46_address_t nh = {
            .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02 + ii),
        };
        adj_index_t ai;

        ai = adj_nbr_add_or_lock(FIB_PROTOCOL_IP4,
                                 VNET_LINK_IP4,
                                 &nh, tm->hw[0]->sw_if_index);

        buckets[ii].type = FT_LB_ADJ;
        buckets[ii].adj.adj = ai;

        bfds[ii].udp.key.peer_addr = nh;
        bfds[ii].udp.key.sw_if_index = tm->hw[0]->sw_if_index;
        bfds[ii].hop_type = BFD_HOP_TYPE_SINGLE;
        bfds[ii].local_state = BFD_STATE_init;
        adj_bfd_notify(BFD_LISTEN_EVENT_CREATE, &bfds[ii]);
        bfds[ii].local_state = BFD_STATE_up;
        adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[ii]);
    }

    for (ii = 0; ii < N_PATHS; ii++)
    {
        fib_route_path_t r_path = {
            .frp_proto = DPO_PROTO_IP4,
            .frp_addr = {
                .ip4.as_u32 = clib_host_to_net_u32(0x0a0a0a02 + ii),
            },
            .frp_sw_if_index = tm->hw[0]->sw_if_index,
            .frp_weight = 1,
            .frp_fib_index = ~0,
        };
        vec_add1(r_paths, r_path);
    };

    pl_index = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED, r_paths);
    fib_path_list_lock(pl_index);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[0],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[3],
                                   &buckets[4],
                                   &buckets[5],
                                   &buckets[6],
                                   &buckets[7],
                                   &buckets[8],
                                   &buckets[9],
                                   &buckets[10],
                                   &buckets[11],
                                   &buckets[12],
                                   &buckets[13],
                                   &buckets[14],
                                   &buckets[15]),
             "Setup OK");

    /* take down paths */
    bfds[0].local_state = BFD_STATE_down;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[0]);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[3],
                                   &buckets[4],
                                   &buckets[5],
                                   &buckets[6],
                                   &buckets[7],
                                   &buckets[8],
                                   &buckets[9],
                                   &buckets[10],
                                   &buckets[11],
                                   &buckets[12],
                                   &buckets[13],
                                   &buckets[14],
                                   &buckets[15]),
             "Failed at shut-down path 0");

    bfds[7].local_state = BFD_STATE_down;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[7]);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[3],
                                   &buckets[4],
                                   &buckets[5],
                                   &buckets[6],
                                   &buckets[2],
                                   &buckets[8],
                                   &buckets[9],
                                   &buckets[10],
                                   &buckets[11],
                                   &buckets[12],
                                   &buckets[13],
                                   &buckets[14],
                                   &buckets[15]),
             "Failed at shut-down path 7");

    /* paths back up */
    bfds[0].local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[0]);
    bfds[7].local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[7]);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[0],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[3],
                                   &buckets[4],
                                   &buckets[5],
                                   &buckets[6],
                                   &buckets[7],
                                   &buckets[8],
                                   &buckets[9],
                                   &buckets[10],
                                   &buckets[11],
                                   &buckets[12],
                                   &buckets[13],
                                   &buckets[14],
                                   &buckets[15]),
             "recovery OK");

    fib_path_list_unlock(pl_index);

    /*
     * non-power of 2 number of buckets
     */
    fib_route_path_t *r_paths2 = NULL;

    r_paths2 = vec_dup(r_paths);
    _vec_len(r_paths2) = 3;

    pl_index = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED, r_paths2);
    fib_path_list_lock(pl_index);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2]),
             "non-power of 2");

    bfds[1].local_state = BFD_STATE_down;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[1]);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    /*
     * path 1's buckets alternate between path 0 and 2
     */
    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[2],
                                   &buckets[0],
                                   &buckets[2],
                                   &buckets[0],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2]),
             "non-power of 2");
    bfds[1].local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[1]);

    fib_path_list_unlock(pl_index);

    /*
     * unequal cost
     */
    fib_route_path_t *r_paths3 = NULL;

    r_paths3 = vec_dup(r_paths);
    _vec_len(r_paths3) = 3;

    r_paths3[0].frp_weight = 3;

    pl_index = fib_path_list_create(FIB_PATH_LIST_FLAG_SHARED, r_paths3);
    fib_path_list_lock(pl_index);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);

    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[1],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0]),
             "UCMP");

    bfds[1].local_state = BFD_STATE_down;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[1]);

    fib_path_list_contribute_forwarding(pl_index,
                                        FIB_FORW_CHAIN_TYPE_UNICAST_IP4,
                                        FIB_PATH_LIST_FWD_FLAG_STICKY,
                                        &dpo);
    /* No attempt to Un-equal distribute the down path's buckets */
    FIB_TEST(!fib_test_validate_lb(&dpo,
                                   16,
                                   &buckets[2],
                                   &buckets[0],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[2],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0],
                                   &buckets[0]),
             "UCMP");
    bfds[1].local_state = BFD_STATE_up;
    adj_bfd_notify(BFD_LISTEN_EVENT_UPDATE, &bfds[1]);

    dpo_reset(&dpo);
    fib_path_list_unlock(pl_index);

    vec_free(r_paths);
    vec_free(r_paths2);
    vec_free(r_paths3);

    FIB_TEST(lb_count == pool_elts(load_balance_pool), "no leaked LBs");
    FIB_TEST(pl_count == fib_path_list_pool_size(), "no leaked PLs");

    return 0;
}

static clib_error_t *
fib_test (vlib_main_t * vm,
          unformat_input_t * input,
          vlib_cli_command_t * cmd_arg)
{
    int res;

    res = 0;

    fib_test_mk_intf(4);

    if (unformat (input, "debug"))
    {
        fib_test_do_debug = 1;
    }

    if (unformat (input, "ip4"))
    {
        res += fib_test_v4();
    }
    else if (unformat (input, "ip6"))
    {
        res += fib_test_v6();
    }
    else if (unformat (input, "ip"))
    {
        res += fib_test_v4();
        res += fib_test_v6();
    }
    else if (unformat (input, "label"))
    {
        res += fib_test_label();
    }
    else if (unformat (input, "ae"))
    {
        res += fib_test_ae();
    }
    else if (unformat (input, "pref"))
    {
        res += fib_test_pref();
    }
    else if (unformat (input, "lfib"))
    {
        res += lfib_test();
    }
    else if (unformat (input, "walk"))
    {
        res += fib_test_walk();
    }
    else if (unformat (input, "bfd"))
    {
        res += fib_test_bfd();
    }
    else if (unformat (input, "inherit"))
    {
        res += fib_test_inherit();
    }
    else if (unformat (input, "sticky"))
    {
        res += fib_test_sticky();
    }
    else
    {
        res += fib_test_v4();
        res += fib_test_v6();
        res += fib_test_ae();
        res += fib_test_bfd();
        res += fib_test_pref();
        res += fib_test_label();
        res += fib_test_inherit();
        res += lfib_test();

        /*
         * fib-walk process must be disabled in order for the walk tests to work
         */
        fib_walk_process_disable();
        res += fib_test_walk();
        fib_walk_process_enable();
    }

    fflush(NULL);
    if (res)
    {
        return clib_error_return(0, "FIB Unit Test Failed");
    }
    else
    {
        return (NULL);
    }
}

VLIB_CLI_COMMAND (test_fib_command, static) = {
    .path = "test fib",
    .short_help = "fib unit tests - DO NOT RUN ON A LIVE SYSTEM",
    .function = fib_test,
};

clib_error_t *
fib_test_init (vlib_main_t *vm)
{
    return 0;
}

VLIB_INIT_FUNCTION (fib_test_init);
