/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#include <lisp/lisp-cp/lisp_types.h>
#include <lisp/lisp-cp/lisp.api_types.h>

int unformat_lisp_eid_api (gid_address_t * dst, u32 vni, const vl_api_eid_t * eid);

void lisp_fid_put_api (vl_api_eid_t * eid, const fid_address_t * fid);

void lisp_gid_put_api (vl_api_eid_t * eid, const gid_address_t * gid);
