/*
 * ipsec_itf.c: IPSec dedicated interface type
 *
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __IPSEC_ITF_H__
#define __IPSEC_ITF_H__

#include <vnet/tunnel/tunnel.h>
#include <vnet/ipsec/ipsec_sa.h>

/**
 * @brief A dedicated IPSec interface type
 *
 * In order to support route based VPNs one needs 3 elements: an interface,
 * for routing to resolve routes through, an SA from the peer to describe
 * security, and encap, to describe how to reach the peer. There are two
 * ways one could model this:
 *
 *  interface + encap + SA = (interface + encap) + SA =
 *          ipip-interface + SA transport mode
 *
 * or
 *
 *  interface + encap + SA = interface + (encap + SA) =
 *          IPSec-interface + SA tunnel mode
 *
 * It's a question of where you add the parenthesis, from the perspective
 * of the external user the effect is identical.
 *
 * The IPsec interface serves as the encap-free interface to be used
 * in conjunction with an encap-describing tunnel mode SA.
 *
 * VPP supports both models, which modelshould you pick?
 * A route based VPN could impose 0, 1 or 2 encaps. the support matrix for
 * these use cases is:
 *
 *        |  0  |  1  |  2  |
 *  --------------------------
 *  ipip  |  N  |  Y  |  Y  |
 *  ipsec |  P  |  Y  |  P  |
 *
 * Where P = potentially.
 * ipsec could potnetially support 0 encap (i.e. transport mode) since neither
 * the interface nor the SA *requires* encap. However, for a route beased VPN
 * to use transport mode is probably wrong since one shouldn't use thransport
 * mode for transit traffic, since without encap it is not guaranteed to return.
 * ipsec could potnetially support 2 encaps, but that would require the SA to
 * describe both, something it does not do at this time.
 *
 * ipsec currently does not support:
 *   - multipoint interfaces
 * but this is only because it is not yet implemented, rather than it cannot
 * be done.
 *
 * Internally the difference is that the midchain adjacency for the IPSec
 * interface has no associated encap (whereas for an ipip tunnel it describes
 * the peer). Consequently, features on the output arc see packets without
 * any encap. Since the protecting SAs are in tunnel mode,
 * they apply the encap. The midchain adj is stacked only once the proctecting
 * SA is known, since only then is the peer known. Otherwise the VLIB graph
 * nodes used are the same:
 *    (routing) --> ipX-michain --> espX-encrypt --> adj-midchain-tx --> (routing)
 * where X = 4 or 6.
 *
 * Some benefits to the ipsec interface:
 *   - it is slightly more efficient since the encapsulating IP header has
 *     its checksum updated only once.
 *   - even when the interface is admin up traffic cannot be sent to a peer
 *     unless the SA is available (since it's the SA that determines the
 *     encap). With ipip interfaces a client must use the admin state to
 *     prevent sending until the SA is available.
 *
 * The best recommendations i can make are:
 *   - pick a model that supports your use case
 *   - make sure any other features you wish to use are supported by the model
 *   - choose the model that best fits your control plane's model.
 *
 *
 * gun reloaded, fire away.
 */
typedef struct ipsec_itf_t_
{
  tunnel_mode_t ii_mode;
  int ii_user_instance;
  u32 ii_sw_if_index;
} __clib_packed ipsec_itf_t;


extern int ipsec_itf_create (u32 user_instance,
			     tunnel_mode_t mode, u32 * sw_if_indexp);
extern int ipsec_itf_delete (u32 sw_if_index);
extern void ipsec_itf_reset_tx_nodes (u32 sw_if_index);

extern void ipsec_itf_adj_stack (adj_index_t ai, u32 sai);
extern void ipsec_itf_adj_unstack (adj_index_t ai);

extern u8 *format_ipsec_itf (u8 * s, va_list * a);

extern ipsec_itf_t *ipsec_itf_get (index_t ii);
extern u32 ipsec_itf_count (void);

typedef walk_rc_t (*ipsec_itf_walk_cb_t) (ipsec_itf_t *itf, void *ctx);
extern void ipsec_itf_walk (ipsec_itf_walk_cb_t cd, void *ctx);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
