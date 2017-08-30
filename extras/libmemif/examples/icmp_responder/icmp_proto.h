/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef _ICMP_PROTO_H_
#define _ICMP_PROTO_H_

int resolve_packet (void *in_pck, ssize_t in_size, void *out_pck,
		    uint32_t * out_size, uint8_t ip_addr[4]);

int print_packet (void *pck);

#endif /* _ICMP_PROTO_H_ */
