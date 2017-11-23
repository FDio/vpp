/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef __AH_H__
#define __AH_H__


#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>


typedef struct
{
  unsigned char nexthdr;
  unsigned char hdrlen;
  unsigned short reserved;
  unsigned int spi;
  unsigned int seq_no;
  unsigned char auth_data[0];
} ah_header_t;


/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  ah_header_t ah;
}) ip4_and_ah_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  ah_header_t ah;
}) ip6_and_ah_header_t;
/* *INDENT-ON* */

#endif /* __AH_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
