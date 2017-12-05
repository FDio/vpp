/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _UPF_SX_H_
#define _UPF_SX_H_

#include <urcu-pointer.h>
#include "upf.h"

#define MAX_LEN 128

upf_node_assoc_t *sx_get_association(pfcp_node_id_t *node_id);
upf_node_assoc_t *sx_new_association(u32 fib_index, ip46_address_t *lcl_addr,
				     ip46_address_t *rmt_addr, pfcp_node_id_t *node_id);
void sx_release_association(upf_node_assoc_t *n);

upf_session_t *sx_create_session(upf_node_assoc_t *assoc, int sx_fib_index,
				 const ip46_address_t *up_address, uint64_t cp_seid,
				 const ip46_address_t *cp_address);
void sx_update_session(upf_session_t *sx);
int sx_disable_session(upf_session_t *sx);
void sx_free_session(upf_session_t *sx);

#define sx_rule_vector_fns(t)						\
upf_##t##_t * sx_get_##t##_by_id(struct rules *,			\
				   typeof (((upf_##t##_t *)0)->id) t##_id);	\
upf_##t##_t *sx_get_##t(upf_session_t *sx, int rule,		\
			  typeof (((upf_##t##_t *)0)->id) t##_id);	\
int sx_create_##t(upf_session_t *sx, upf_##t##_t *t);		\
int sx_delete_##t(upf_session_t *sx, u32 t##_id);			\

sx_rule_vector_fns(pdr)
sx_rule_vector_fns(far)
sx_rule_vector_fns(urr)

void sx_send_end_marker(upf_session_t *sx, u16 id);

#undef sx_rule_vector_fns

int sx_update_apply(upf_session_t *sx);
void sx_update_finish(upf_session_t *sx);

upf_session_t *sx_lookup(uint64_t sess_id);

void sx_session_dump_tbls(void);

static inline struct rules *sx_get_rules(upf_session_t *sx, int rules)
{
	return &sx->rules[sx->active ^ rules];
}

void vlib_free_combined_counter (vlib_combined_counter_main_t * cm);

u32 process_urrs(vlib_main_t *vm, upf_session_t *sess,
		 struct rules *r,
		 upf_pdr_t *pdr, vlib_buffer_t * b,
		 u8 is_dl, u8 is_ul,
		 u32 next);

void upf_pfcp_error_report(upf_session_t * sx, gtp_error_ind_t * error);

/* format functions */
u8 * format_sx_node_association(u8 * s, va_list * args);
u8 * format_sx_session(u8 * s, va_list * args);
u8 * format_pfcp_endpoint(u8 * s, va_list * args);

/**
 * Compare integer ids.
 */
#define intcmp(a, b)                                    \
	({                                              \
		typeof (a) a_ = (a);                    \
		typeof (b) b_ = (b);                    \
		(a_) < (b_) ? -1 : (a_) > (b_) ? 1 : 0; \
	})

static inline int ipfilter_address_cmp_const(const ipfilter_address_t *a, const ipfilter_address_t b)
{
  int r;

  if ((r = intcmp(a->address.as_u64[0], b.address.as_u64[0])) != 0)
    return r;
  if ((r = intcmp(a->address.as_u64[1], b.address.as_u64[1])) != 0)
    return r;
  return intcmp(a->mask, b.mask);
};

#endif /* _UPF_SX_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
