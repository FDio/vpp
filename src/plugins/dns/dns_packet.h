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

#ifndef included_dns_packet_h
#define included_dns_packet_h

/**
 * DNS packet header format
 */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u16 id;                       /**< transaction ID */
  u16 flags;                    /**< flags  */
  u16 qdcount;                  /**< number of questions */
  u16 anscount;                 /**< number of answers */
  u16 nscount;                  /**< number of name servers */
  u16 arcount;                  /**< number of additional records */
}) dns_header_t;
/* *INDENT-ON* */

#define DNS_RCODE_MASK (0xf)
#define DNS_RCODE_NO_ERROR 0
#define DNS_RCODE_FORMAT_ERROR 1
#define DNS_RCODE_SERVER_FAILURE 2
#define DNS_RCODE_NAME_ERROR 3
#define DNS_RCODE_NOT_IMPLEMENTED 4
#define DNS_RCODE_REFUSED 5

#define DNS_RA (1<<7)		/**< recursion available */
#define DNS_RD (1<<8)		/**< recursion desired */
#define DNS_TC (1<<9)	       /**< truncation  */
#define DNS_AA (1<<10)		/**< authoritative answer  */
#define DNS_OPCODE_MASK (0xf<<11) /**< opcode mask */
#define DNS_OPCODE_QUERY (0<<11)  /**< standard query */
#define DNS_OPCODE_IQUERY (1<<11) /**< inverse query (deprecated) */
#define DNS_OPCODE_STATUS (2<<11) /**< server status  */
#define DNS_QR (1<<15)		/**< query=0, response=1  */


/*
 * Note: in DNS-land, www.foobar.com is encoded as three "labels,"
 * each of which amount to a 1 octet length followed by up to 63
 * octets of name. Don't forget to add a "null root label" after the last
 * real one, or the poor slob trying to parse the name will have
 * no chance whatsoever.
 *
 * All RRs have the same top level format shown below:
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |
 *    /                                               /
 *    /                      NAME                     /
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TYPE                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     CLASS                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TTL                      |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   RDLENGTH                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *    /                     RDATA                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 *
 *  DNS "questions" have the following format:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                     QNAME                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QTYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QCLASS                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

/**
 * DNS "question" fixed header.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u16 type;	/**< record type requested */
  u16 class;	/**< class, 1 = internet */
}) dns_query_t;
/* *INDENT-ON* */

/**
 * DNS RR fixed header.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u16 type;	/**< record type */
  u16 class;	/**< class, 1 = internet */
  u32 ttl;	/**< time to live, in seconds */
  u16 rdlength;
  /**< length of r */
  u8 rdata[0];
}) dns_rr_t;
/* *INDENT-ON* */

/*
 * There are quite a number of DNS record types
 * Feel free to add as needed
 */
#define foreach_dns_type                        \
_(A, 1) 	/**< ip4 host address */        \
_(AAAA, 28)     /**< ip6 host address */        \
_(ALL, 255)     /**< all available data */      \
_(TEXT, 16)     /**< a text string */           \
_(NAMESERVER, 2) /**< a nameserver */           \
_(CNAME, 5)      /**< a CNAME (alias) */	\
_(MAIL_EXCHANGE, 15) /**< a mail exchange  */	\
_(PTR, 12)      /**< a PTR (pointer) record */	\
_(HINFO, 13)	/**< Host info */

typedef enum
{
#define _(name,value) DNS_TYPE_##name = value,
  foreach_dns_type
#undef _
} dns_type_t;

#define DNS_CLASS_IN	1	/**< The Internet */


#endif /* included_dns_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
