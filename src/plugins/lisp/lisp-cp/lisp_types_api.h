/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <lisp/lisp-cp/lisp_types.h>
#include <lisp/lisp-cp/lisp.api_types.h>

int unformat_lisp_eid_api (gid_address_t * dst, u32 vni, const vl_api_eid_t * eid);

void lisp_fid_put_api (vl_api_eid_t * eid, const fid_address_t * fid);

void lisp_gid_put_api (vl_api_eid_t * eid, const gid_address_t * gid);
