/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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


#include <filter/filter_table.h>
#include <filter/filter_hook.h>
#include <filter/filter_chain.h>
#include <filter/filter_rule.h>
#include <filter/filter_target_jump.h>
#include <filter/filter_target_accept.h>
#include <filter/filter_target_terminate.h>
#include <filter/filter_target_return.h>
#include <filter/filter_target_drop.h>
#include <filter/filter_match_ip.h>

static int filter_test_do_debug;

#define FILTER_TEST_I(_cond, _comment, _args...)                \
({								\
    int _evald = (_cond);					\
    if (!(_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
        res = 1;                                                \
    } else {							\
        if (filter_test_do_debug)                               \
            fformat(stderr, "PASS:%d: " _comment "\n",          \
                    __LINE__, ##_args);				\
    }								\
    res;							\
})
#define FILTER_TEST(_cond, _comment, _args...)			\
{								\
    if (FILTER_TEST_I(_cond, _comment, ##_args)) {              \
    return (1);                                                 \
        ASSERT(!("FAIL: " _comment));				\
    }								\
}
#define FILTER_TEST_RV_I(_cond, _comment, _args...)             \
({								\
    int _evald = (_cond);					\
    if ((_evald)) {						\
        fformat(stderr, "FAIL:%d: " _comment "\n",		\
                __LINE__, ##_args);				\
        res = 1;                                                \
    } else {							\
        if (filter_test_do_debug)                               \
            fformat(stderr, "PASS:%d: " _comment "\n",          \
                    __LINE__, ##_args);				\
    }								\
    res;							\
})
#define FILTER_TEST_RV(_cond, _comment, _args...)               \
{								\
  if (FILTER_TEST_RV_I(_cond, _comment, ##_args)) {             \
    return (1);                                                 \
        ASSERT(!("FAIL: " _comment));				\
    }								\
}

static int
filter_test (void)
{
  u8 *ft_name_1;
  index_t fti_1;
  int res = 0;

  ft_name_1 = format (NULL, "table_1");

  /*
   * create and delete table_1
   */
  FILTER_TEST_RV (filter_table_update (ft_name_1, DPO_PROTO_IP4,
				       2, &fti_1), "Create Table 1");

  FILTER_TEST_RV (filter_table_delete (ft_name_1, DPO_PROTO_IP4),
		  "Delete Table 1");

  FILTER_TEST (0 == filter_table_n_elts (), "Table pool empty");

  /*
   * recreate table 1
   */
  FILTER_TEST_RV (filter_table_update (ft_name_1, DPO_PROTO_IP4,
				       2, &fti_1), "Create Table 1");

  /*
   * add a chain at the input hook which accepts packets when the end of the
   * chain is reached
   */
  u8 *fc_name_1_1 = format (NULL, "chain_1_1");
  index_t fci_1_1;

  FILTER_TEST_RV (filter_table_chain_add (fti_1, fc_name_1_1,
					  FILTER_HOOK_INPUT,
					  FILTER_CHAIN_POLICY_ACCEPT,
					  2, &fci_1_1),
		  "Create chain 1 in table 1");

  /* the hook should be inplace with a jump to the new chain */
  const filter_target_jump_t *ftj_c_1_1;
  const filter_target_accept_t *fta_c_1_1;
  index_t ftji_c_1_1, ftai_c_1_1;
  const dpo_id_t *hook_dpo;

  hook_dpo = filter_hook_root_get (DPO_PROTO_IP4, FILTER_HOOK_INPUT);
  ftji_c_1_1 = hook_dpo->dpoi_index;
  ftj_c_1_1 = filter_target_jump_get (ftji_c_1_1);

  FILTER_TEST (ftj_c_1_1->ftj_rule == INDEX_INVALID, "jump chain");
  FILTER_TEST (ftj_c_1_1->ftj_chain == fci_1_1, "jump chain");

  /* it should be stacked on the chains terminator, which should be an accept */
  ftai_c_1_1 = ftj_c_1_1->ftj_next.dpoi_index;
  fta_c_1_1 = filter_target_accept_get (ftai_c_1_1);
  /* the jump should push the terminate since there are no more chains nor tables */
  FILTER_TEST (0 == dpo_cmp (&ftj_c_1_1->ftj_push,
			     filter_target_terminate_get (DPO_PROTO_IP4,
							  FILTER_HOOK_INPUT)),
	       "jump pushes terminate");


  FILTER_TEST (fta_c_1_1->fta_table == fti_1, "accept in correct table");

  /* it should be stacked on the terminate, since this is the last table
   * and last chain */
  FILTER_TEST (0 == dpo_cmp (&fta_c_1_1->fta_next[FILTER_HOOK_INPUT],
			     filter_target_terminate_get (DPO_PROTO_IP4,
							  FILTER_HOOK_INPUT)),
	       "Accept stacks on terminate");

  /*
   * add a second chain with a better precedence at the input hook with
   * an accept policy
   */
  u8 *fc_name_1_2 = format (NULL, "chain_1_2");
  index_t fci_1_2;

  FILTER_TEST_RV (filter_table_chain_add (fti_1, fc_name_1_2,
					  FILTER_HOOK_INPUT,
					  FILTER_CHAIN_POLICY_ACCEPT,
					  10, &fci_1_2),
		  "Create chain 2 in table 1");

  /* check that this new chain's jump and terminating accept stack correctly
   *  1; the chain's jump stacks on a return, since there is a chain after it
   *  2; the hook updates since this is the best chain  */
  const filter_target_jump_t *ftj_c_1_2;
  const filter_target_return_t *ftr_c_1_2;
  index_t ftji_c_1_2, ftri_c_1_2;

  hook_dpo = filter_hook_root_get (DPO_PROTO_IP4, FILTER_HOOK_INPUT);
  ftji_c_1_2 = hook_dpo->dpoi_index;
  ftj_c_1_2 = filter_target_jump_get (ftji_c_1_2);

  FILTER_TEST (ftj_c_1_2->ftj_chain == fci_1_2, "hook jumps to chain 2");
  FILTER_TEST (0 == dpo_cmp (&ftj_c_1_2->ftj_push,
			     filter_chain_jump_dpo_get (fci_1_1)),
	       "jump 2 pushes next chain");
  ftri_c_1_2 = ftj_c_1_2->ftj_next.dpoi_index;
  ftr_c_1_2 = filter_target_return_get (ftri_c_1_2);

  FILTER_TEST (NULL != ftr_c_1_2, "chain 2 jumps to return");

  /*
   * add a thrid chain with a precedence in between the 2 that exist at the input hook with
   * an accept policy
   */
  u8 *fc_name_1_3 = format (NULL, "chain_1_3");
  index_t fci_1_3;

  FILTER_TEST_RV (filter_table_chain_add (fti_1, fc_name_1_3,
					  FILTER_HOOK_INPUT,
					  FILTER_CHAIN_POLICY_ACCEPT,
					  7, &fci_1_3),
		  "Create chain 3 in table 1");

  /* validation:
   *  1; the hook is still chain2
   *  2; chain 3's jump is to a return
   *  3; chain 2's jump pushes chain 3's jump
   */
  const filter_target_jump_t *ftj_c_1_3;
  const filter_target_return_t *ftr_c_1_3;
  index_t ftji_c_1_3, ftri_c_1_3;

  hook_dpo = filter_hook_root_get (DPO_PROTO_IP4, FILTER_HOOK_INPUT);
  FILTER_TEST (ftji_c_1_2 == hook_dpo->dpoi_index, "hook stil chain 2");

  ftji_c_1_3 = filter_chain_jump_dpo_get (fci_1_3)->dpoi_index;
  ftj_c_1_3 = filter_target_jump_get (ftji_c_1_3);
  ftri_c_1_3 = ftj_c_1_3->ftj_next.dpoi_index;
  ftr_c_1_3 = filter_target_return_get (ftri_c_1_3);
  FILTER_TEST (NULL != ftr_c_1_3, "chain 3 jumps to return");

  ftji_c_1_2 = filter_chain_jump_dpo_get (fci_1_2)->dpoi_index;
  ftj_c_1_2 = filter_target_jump_get (ftji_c_1_2);
  FILTER_TEST (0 ==
	       dpo_cmp (&ftj_c_1_2->ftj_push,
			filter_chain_jump_dpo_get (fci_1_3)),
	       "jump 2 pushes next chain");

  /*
   * Add a rule to the worst precedence chain (#2)
   */
  u8 *fr_name_1_2_1 = format (NULL, "rule_1_2_1");
  dpo_id_t match_1_2_1 = DPO_INVALID, target_1_2_1 = DPO_INVALID;
  const ip46_address_t ip = {
    .ip4 = {
	    .as_u32 = clib_host_to_net_u32 (0xc0c0c0c0),
	    }
  };
  index_t fri_1_2_1;

  FILTER_TEST_RV (filter_match_ip_add_and_lock (DPO_PROTO_IP4,
						FILTER_MATCH_SRC,
						&ip,
						&match_1_2_1),
		  "match create error");
  FILTER_TEST_RV (filter_target_drop_add_and_lock (DPO_PROTO_IP4,
						   &target_1_2_1),
		  "drop target create error");

  FILTER_TEST_RV (filter_table_rule_append (fti_1, fc_name_1_2,
					    fr_name_1_2_1,
					    &match_1_2_1,
					    &target_1_2_1,
					    &fri_1_2_1),
		  "Create rule 1 chain 2 table 1");

  /* validation:
   * 1; chain 2's jump now stacks to the rule's match
   * 2; the match's false result is the chain's terminator, the true result
   *    is the drop target
   */
  filter_match_ip_t *fmi_1_2_1;

  ftji_c_1_2 = filter_chain_jump_dpo_get (fci_1_2)->dpoi_index;
  ftj_c_1_2 = filter_target_jump_get (ftji_c_1_2);
  FILTER_TEST (0 == dpo_cmp (&ftj_c_1_2->ftj_next, &match_1_2_1),
	       "jump 2 jumps to match");

  fmi_1_2_1 = filter_match_ip_get (match_1_2_1.dpoi_index);
  FILTER_TEST (filter_target_is_return
	       (&fmi_1_2_1->fmi_base.fm_results[FILTER_MATCH_NO]),
	       "match 1 false jumps to chain terminator");
  FILTER_TEST (0 ==
	       dpo_cmp (&fmi_1_2_1->fmi_base.fm_results[FILTER_MATCH_YES],
			&target_1_2_1),
	       "match 1 true jumps to rule 1 target");

  /*
   * Add another rule to the worst precedence chain (#2)
   */
  u8 *fr_name_1_2_2 = format (NULL, "rule_1_2_2");
  dpo_id_t match_1_2_2 = DPO_INVALID, target_1_2_2 = DPO_INVALID;
  index_t fri_1_2_2;

  FILTER_TEST_RV (filter_match_ip_add_and_lock (DPO_PROTO_IP4,
						FILTER_MATCH_SRC,
						&ip,
						&match_1_2_2),
		  "match create error");
  FILTER_TEST_RV (filter_target_drop_add_and_lock (DPO_PROTO_IP4,
						   &target_1_2_2),
		  "drop target create error");

  FILTER_TEST_RV (filter_table_rule_append (fti_1, fc_name_1_2,
					    fr_name_1_2_2,
					    &match_1_2_2,
					    &target_1_2_2,
					    &fri_1_2_2),
		  "Create rule 2 chain 2 table 1");

  /* validation:
   * 1; chain 2's jump still stacks on rule 1's match
   * 2; rule 2's match false result is the chain's terminator, the true result
   *    is the drop target
   * 3; rule 1's match false is the new rule
   */
  filter_match_ip_t *fmi_1_2_2;

  ftji_c_1_2 = filter_chain_jump_dpo_get (fci_1_2)->dpoi_index;
  ftj_c_1_2 = filter_target_jump_get (ftji_c_1_2);
  FILTER_TEST (0 == dpo_cmp (&ftj_c_1_2->ftj_next, &match_1_2_1),
	       "jump 2 jumps to match 1");

  fmi_1_2_2 = filter_match_ip_get (match_1_2_2.dpoi_index);
  FILTER_TEST (filter_target_is_return
	       (&fmi_1_2_2->fmi_base.fm_results[FILTER_MATCH_NO]),
	       "match 2 false jumps to chain terminator");
  FILTER_TEST (0 ==
	       dpo_cmp (&fmi_1_2_2->fmi_base.fm_results[FILTER_MATCH_YES],
			&target_1_2_2),
	       "match 2 true jumps to rule 2 target");

  fmi_1_2_1 = filter_match_ip_get (match_1_2_1.dpoi_index);
  FILTER_TEST (0 == dpo_cmp (&fmi_1_2_1->fmi_base.fm_results[FILTER_MATCH_NO],
			     &match_1_2_2),
	       "match 1 false jumps to rule 2 match");

  /*
   * add a branch chain with a acceot policy
   */
  u8 *fc_name_1_4 = format (NULL, "chain_1_4");
  index_t fci_1_4;

  FILTER_TEST_RV (filter_table_chain_add (fti_1, fc_name_1_4,
					  FILTER_HOOK_BRANCH,
					  FILTER_CHAIN_POLICY_ACCEPT,
					  ~0, &fci_1_4),
		  "Create chain 4 in table 1");

  /* validation:
   *  1; the hook is still chain2
   *  2; chain 4's jump is to an accepot
   *  3; chain 4's accept is to terminate
   */
  const filter_target_jump_t *ftj_c_1_4;
  const filter_target_accept_t *fta_c_1_4;
  index_t ftji_c_1_4, ftai_c_1_4;

  ftji_c_1_4 = filter_chain_jump_dpo_get (fci_1_4)->dpoi_index;
  ftj_c_1_4 = filter_target_jump_get (ftji_c_1_4);
  FILTER_TEST (filter_target_is_accept (&ftj_c_1_4->ftj_next),
	       "chain 4 jump to accept");
  ftai_c_1_4 = ftj_c_1_4->ftj_next.dpoi_index;
  fta_c_1_4 = filter_target_accept_get (ftai_c_1_4);
  FILTER_TEST (0 == dpo_cmp (&fta_c_1_4->fta_next[FILTER_HOOK_INPUT],
			     filter_target_terminate_get (DPO_PROTO_IP4,
							  FILTER_HOOK_INPUT)),
	       "Accept 4 stacks on terminate");

  /*
   * Append rule 3 to chain 2, that jumps to chain 4
   */
  u8 *fr_name_1_2_3 = format (NULL, "rule_1_2_3");
  dpo_id_t match_1_2_3 = DPO_INVALID, target_1_2_3 = DPO_INVALID;
  index_t fri_1_2_3;

  FILTER_TEST_RV (filter_match_ip_add_and_lock (DPO_PROTO_IP4,
						FILTER_MATCH_SRC,
						&ip,
						&match_1_2_3),
		  "match create error");
  FILTER_TEST_RV (filter_target_jump_add_and_lock (DPO_PROTO_IP4,
						   fci_1_4,
						   &target_1_2_3),
		  "jump target create error");

  FILTER_TEST_RV (filter_table_rule_append (fti_1, fc_name_1_2,
					    fr_name_1_2_3,
					    &match_1_2_3,
					    &target_1_2_3,
					    &fri_1_2_3),
		  "Create rule 3 chain 2 table 1");

  /* validation:
   * 1; rule 3's match false result is the chain's terminator, the true result
   *    is the drop target
   * 2; rule 2's match false is the new rule
   */
  filter_match_ip_t *fmi_1_2_3;

  fmi_1_2_3 = filter_match_ip_get (match_1_2_3.dpoi_index);
  FILTER_TEST (filter_target_is_return
	       (&fmi_1_2_3->fmi_base.fm_results[FILTER_MATCH_NO]),
	       "match 3 false jumps to chain terminator");
  FILTER_TEST (0 ==
	       dpo_cmp (&fmi_1_2_3->fmi_base.fm_results[FILTER_MATCH_YES],
			&target_1_2_3),
	       "match 3 true jumps to rule 2 target");

  fmi_1_2_2 = filter_match_ip_get (match_1_2_2.dpoi_index);
  FILTER_TEST (0 == dpo_cmp (&fmi_1_2_2->fmi_base.fm_results[FILTER_MATCH_NO],
			     &match_1_2_3),
	       "match 1 false jumps to rule 2 match");

  /*
   * add a rule into chain 4 (the branch chain)
   */
  u8 *fr_name_1_4_1 = format (NULL, "rule_1_4_1");
  dpo_id_t match_1_4_1 = DPO_INVALID, target_1_4_1 = DPO_INVALID;
  index_t fri_1_4_1;

  FILTER_TEST_RV (filter_match_ip_add_and_lock (DPO_PROTO_IP4,
						FILTER_MATCH_SRC,
						&ip,
						&match_1_4_1),
		  "match create error");
  FILTER_TEST_RV (filter_target_drop_add_and_lock (DPO_PROTO_IP4,
						   &target_1_4_1),
		  "drop target create error");

  FILTER_TEST_RV (filter_table_rule_append (fti_1, fc_name_1_4,
					    fr_name_1_4_1,
					    &match_1_4_1,
					    &target_1_4_1,
					    &fri_1_4_1),
		  "Create rule 1 chain 4 table 1");

  /* validation:
   * 1; rule 4's match false result is the chain's terminator, the true result
   *    is the drop target
   * 2; the jump of chain 2 rule 3 points to match on rule 1 chain 4.
   */
  const filter_target_jump_t *ftj_1_2_3;
  const filter_match_ip_t *fmi_1_4_1;

  fmi_1_4_1 = filter_match_ip_get (match_1_4_1.dpoi_index);
  FILTER_TEST (filter_target_is_accept
	       (&fmi_1_4_1->fmi_base.fm_results[FILTER_MATCH_NO]),
	       "match 3 false jumps to chain terminator");
  FILTER_TEST (0 ==
	       dpo_cmp (&fmi_1_4_1->fmi_base.fm_results[FILTER_MATCH_YES],
			&target_1_4_1),
	       "match 3 true jumps to rule 4 target");

  ftj_1_2_3 = filter_target_jump_get (target_1_2_3.dpoi_index);
  FILTER_TEST (0 == dpo_cmp (&ftj_1_2_3->ftj_next, &match_1_4_1),
	       "jump chain 2 rule 3 jumps to match rule 1 chain 4");

  /*
   * cleanup
   */
  FILTER_TEST_RV (filter_table_rule_delete
		  (fti_1, fc_name_1_2, fr_name_1_2_1),
		  "remove rule 1, chain 2, table 1");
  FILTER_TEST_RV (filter_table_rule_delete
		  (fti_1, fc_name_1_2, fr_name_1_2_2),
		  "remove rule 2, chain 2, table 1");
  FILTER_TEST_RV (filter_table_rule_delete
		  (fti_1, fc_name_1_2, fr_name_1_2_3),
		  "remove rule 3, chain 2, table 1");
  FILTER_TEST_RV (filter_table_rule_delete
		  (fti_1, fc_name_1_4, fr_name_1_4_1),
		  "remove rule 1, chain 4, table 1");
  FILTER_TEST_RV (filter_table_chain_delete (fti_1, fc_name_1_4),
		  "remove chain 4, table 1");
  FILTER_TEST_RV (filter_table_chain_delete (fti_1, fc_name_1_3),
		  "remove chain 3, table 1");
  FILTER_TEST_RV (filter_table_chain_delete (fti_1, fc_name_1_2),
		  "remove chain 2, table 1");
  FILTER_TEST_RV (filter_table_chain_delete (fti_1, fc_name_1_1),
		  "remove chain 1, table 1");
  FILTER_TEST_RV (filter_table_delete_index (fti_1), "remove table 1");

  dpo_reset (&target_1_2_3);
  dpo_reset (&match_1_2_3);
  dpo_reset (&target_1_2_2);
  dpo_reset (&match_1_2_2);
  dpo_reset (&target_1_2_1);
  dpo_reset (&match_1_2_1);
  dpo_reset (&target_1_4_1);
  dpo_reset (&match_1_4_1);

  FILTER_TEST (0 == filter_rule_n_elts (),
	       "filter rule pool empty: %d", filter_rule_n_elts ());
  FILTER_TEST (0 == filter_chain_n_elts (),
	       "filter chain pool empty: %d", filter_chain_n_elts ());
  FILTER_TEST (0 == filter_table_n_elts (), "filter table pool empty");
  FILTER_TEST (0 == pool_elts (filter_target_jump_pool),
	       "target jump pool empty");
  FILTER_TEST (0 == pool_elts (filter_target_return_pool),
	       "target return pool empty");
  FILTER_TEST (0 == pool_elts (filter_target_accept_pool),
	       "target accept pool empty");
  FILTER_TEST (0 == pool_elts (filter_target_drop_pool),
	       "target drop pool empty");
  FILTER_TEST (0 == pool_elts (filter_match_ip_pool), "match ip pool empty");

  return (0);
}

static clib_error_t *
filter_test_cli (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd_arg)
{
  if (filter_test ())
    return clib_error_return (0, "Filter Unit Test Failed");

  return (NULL);
}

VLIB_CLI_COMMAND (test_filter_command, static) =
{
.path = "test filter",.short_help =
    "filter unit tests - DO NOT RUN ON A LIVE SYSTEM",.function =
    filter_test_cli,};

clib_error_t *
filter_test_init (vlib_main_t * vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (filter_test_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
