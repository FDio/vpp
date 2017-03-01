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

#ifndef __FIB_TEST_H__
#define __FIB_TEST_H__

#include <vnet/fib/fib_types.h>

typedef enum fib_test_lb_bucket_type_t_ {
    FT_LB_LABEL_O_ADJ,
    FT_LB_LABEL_STACK_O_ADJ,
    FT_LB_LABEL_O_LB,
    FT_LB_O_LB,
    FT_LB_SPECIAL,
    FT_LB_ADJ,
    FT_LB_INTF,
} fib_test_lb_bucket_type_t;

typedef struct fib_test_lb_bucket_t_ {
    fib_test_lb_bucket_type_t type;

    union
    {
	struct
	{
	    mpls_eos_bit_t eos;
	    mpls_label_t label;
	    u8 ttl;
	    adj_index_t adj;
	} label_o_adj;
	struct
	{
	    mpls_eos_bit_t eos;
	    mpls_label_t label_stack[8];
	    u8 label_stack_size;
	    u8 ttl;
	    adj_index_t adj;
	} label_stack_o_adj;
	struct
	{
	    mpls_eos_bit_t eos;
	    mpls_label_t label;
	    u8 ttl;
	    index_t lb;
	} label_o_lb;
	struct
	{
	    index_t adj;
	} adj;
	struct
	{
	    index_t lb;
	} lb;
	struct
	{
	    index_t adj;
	} special;
    };
} fib_test_lb_bucket_t;

typedef enum fib_test_rep_bucket_type_t_ {
    FT_REP_LABEL_O_ADJ,
    FT_REP_INTF,
} fib_test_rep_bucket_type_t;

typedef struct fib_test_rep_bucket_t_ {
    fib_test_rep_bucket_type_t type;

    union
    {
	struct
	{
	    mpls_eos_bit_t eos;
	    mpls_label_t label;
	    u8 ttl;
	    adj_index_t adj;
	} label_o_adj;
 	struct
	{
	    adj_index_t adj;
	} adj;
   };
} fib_test_rep_bucket_t;


extern int fib_test_validate_rep_v(const replicate_t *rep,
                                   u16 n_buckets,
                                   va_list ap);

extern int fib_test_validate_lb_v(const load_balance_t *lb,
                                  u16 n_buckets,
                                  va_list ap);

extern int fib_test_validate_entry(fib_node_index_t fei,
                                   fib_forward_chain_type_t fct,
                                   u16 n_buckets,
                                   ...);

#endif
