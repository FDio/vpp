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
#ifndef included_vnet_api_errno_h
#define included_vnet_api_errno_h

#include <stdarg.h>
#include <vppinfra/types.h>
#include <vppinfra/format.h>

#define foreach_vnet_api_error						\
_(VNET_API_ERROR_UNSPECIFIED, -1, "VNET_API_ERROR_UNSPECIFIED: Unspecified Error")                                 \
_(VNET_API_ERROR_INVALID_SW_IF_INDEX, -2, "VNET_API_ERROR_INVALID_SW_IF_INDEX: Invalid sw_if_index")                       \
_(VNET_API_ERROR_NO_SUCH_FIB, -3, "VNET_API_ERROR_NO_SUCH_FIB: No such FIB / VRF")                                 \
_(VNET_API_ERROR_NO_SUCH_INNER_FIB, -4, "VNET_API_ERROR_NO_SUCH_INNER_FIB: No such inner FIB / VRF")                     \
_(VNET_API_ERROR_NO_SUCH_LABEL, -5, "VNET_API_ERROR_NO_SUCH_LABEL: No such label")                                   \
_(VNET_API_ERROR_NO_SUCH_ENTRY, -6, "VNET_API_ERROR_NO_SUCH_ENTRY: No such entry")                                   \
_(VNET_API_ERROR_INVALID_VALUE, -7, "VNET_API_ERROR_INVALID_VALUE: Invalid value")                                   \
_(VNET_API_ERROR_INVALID_VALUE_2, -8, "VNET_API_ERROR_INVALID_VALUE_2: Invalid value #2")                              \
_(VNET_API_ERROR_UNIMPLEMENTED, -9, "VNET_API_ERROR_UNIMPLEMENTED: Unimplemented")                                   \
_(VNET_API_ERROR_INVALID_SW_IF_INDEX_2, -10, "VNET_API_ERROR_INVALID_SW_IF_INDEX_2: Invalid sw_if_index #2")                 \
_(VNET_API_ERROR_SYSCALL_ERROR_1, -11, "VNET_API_ERROR_SYSCALL_ERROR_1: System call error #1")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_2, -12, "VNET_API_ERROR_SYSCALL_ERROR_2: System call error #2")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_3, -13, "VNET_API_ERROR_SYSCALL_ERROR_3: System call error #3")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_4, -14, "VNET_API_ERROR_SYSCALL_ERROR_4: System call error #4")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_5, -15, "VNET_API_ERROR_SYSCALL_ERROR_5: System call error #5")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_6, -16, "VNET_API_ERROR_SYSCALL_ERROR_6: System call error #6")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_7, -17, "VNET_API_ERROR_SYSCALL_ERROR_7: System call error #7")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_8, -18, "VNET_API_ERROR_SYSCALL_ERROR_8: System call error #8")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_9, -19, "VNET_API_ERROR_SYSCALL_ERROR_9: System call error #9")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_10, -20, "VNET_API_ERROR_SYSCALL_ERROR_10: System call error #10")                       \
_(VNET_API_ERROR_FEATURE_DISABLED, -30, "VNET_API_ERROR_FEATURE_DISABLED: Feature disabled by configuration")           \
_(VNET_API_ERROR_INVALID_REGISTRATION, -31, "VNET_API_ERROR_INVALID_REGISTRATION: Invalid registration")                    \
_(VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB, -50, "VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB: Next hop not in FIB")                      \
_(VNET_API_ERROR_UNKNOWN_DESTINATION, -51, "VNET_API_ERROR_UNKNOWN_DESTINATION: Unknown destination")                      \
_(VNET_API_ERROR_NO_PATHS_IN_ROUTE, -52, "VNET_API_ERROR_NO_PATHS_IN_ROUTE: No paths specified in route")                \
_(VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP, -53, "VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP: Next hop not found (multipath)")         \
_(VNET_API_ERROR_NO_MATCHING_INTERFACE, -54, "VNET_API_ERROR_NO_MATCHING_INTERFACE: No matching interface for probe")        \
_(VNET_API_ERROR_INVALID_VLAN, -55, "VNET_API_ERROR_INVALID_VLAN: Invalid VLAN")                                    \
_(VNET_API_ERROR_VLAN_ALREADY_EXISTS, -56, "VNET_API_ERROR_VLAN_ALREADY_EXISTS: VLAN subif already exists")                \
_(VNET_API_ERROR_INVALID_SRC_ADDRESS, -57, "VNET_API_ERROR_INVALID_SRC_ADDRESS: Invalid src address")                      \
_(VNET_API_ERROR_INVALID_DST_ADDRESS, -58, "VNET_API_ERROR_INVALID_DST_ADDRESS: Invalid dst address")                      \
_(VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH, -59, "VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH: Address length mismatch")              \
_(VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE, -60, "VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE: Address not found for interface") \
_(VNET_API_ERROR_ADDRESS_NOT_DELETABLE, -61, "VNET_API_ERROR_ADDRESS_NOT_DELETABLE: Address not deletable")                  \
_(VNET_API_ERROR_IP6_NOT_ENABLED, -62, "VNET_API_ERROR_IP6_NOT_ENABLED: ip6 not enabled")				\
_(VNET_API_ERROR_NO_SUCH_NODE, -63, "VNET_API_ERROR_NO_SUCH_NODE: No such graph node")				\
_(VNET_API_ERROR_NO_SUCH_NODE2, -64, "VNET_API_ERROR_NO_SUCH_NODE2: No such graph node #2")				\
_(VNET_API_ERROR_NO_SUCH_TABLE, -65, "VNET_API_ERROR_NO_SUCH_TABLE: No such table")                                  \
_(VNET_API_ERROR_NO_SUCH_TABLE2, -66, "VNET_API_ERROR_NO_SUCH_TABLE2: No such table #2")                              \
_(VNET_API_ERROR_NO_SUCH_TABLE3, -67, "VNET_API_ERROR_NO_SUCH_TABLE3: No such table #3")                              \
_(VNET_API_ERROR_SUBIF_ALREADY_EXISTS, -68, "VNET_API_ERROR_SUBIF_ALREADY_EXISTS: Subinterface already exists")             \
_(VNET_API_ERROR_SUBIF_CREATE_FAILED, -69, "VNET_API_ERROR_SUBIF_CREATE_FAILED: Subinterface creation failed")		\
_(VNET_API_ERROR_INVALID_MEMORY_SIZE, -70, "VNET_API_ERROR_INVALID_MEMORY_SIZE: Invalid memory size requested")            \
_(VNET_API_ERROR_INVALID_INTERFACE, -71, "VNET_API_ERROR_INVALID_INTERFACE: Invalid interface")                          \
_(VNET_API_ERROR_INVALID_VLAN_TAG_COUNT, -72, "VNET_API_ERROR_INVALID_VLAN_TAG_COUNT: Invalid number of tags for requested operation") \
_(VNET_API_ERROR_INVALID_ARGUMENT, -73, "VNET_API_ERROR_INVALID_ARGUMENT: Invalid argument")                            \
_(VNET_API_ERROR_UNEXPECTED_INTF_STATE, -74, "VNET_API_ERROR_UNEXPECTED_INTF_STATE: Unexpected interface state")             \
_(VNET_API_ERROR_TUNNEL_EXIST, -75, "VNET_API_ERROR_TUNNEL_EXIST: Tunnel already exists")                           \
_(VNET_API_ERROR_INVALID_DECAP_NEXT, -76, "VNET_API_ERROR_INVALID_DECAP_NEXT: Invalid decap-next")			\
_(VNET_API_ERROR_RESPONSE_NOT_READY, -77, "VNET_API_ERROR_RESPONSE_NOT_READY: Response not ready")			\
_(VNET_API_ERROR_NOT_CONNECTED, -78, "VNET_API_ERROR_NOT_CONNECTED: Not connected to the data plane")                \
_(VNET_API_ERROR_IF_ALREADY_EXISTS, -79, "VNET_API_ERROR_IF_ALREADY_EXISTS: Interface already exists")                   \
_(VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED, -80, "VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED: Operation not allowed on slave of BondEthernet") \
_(VNET_API_ERROR_VALUE_EXIST, -81, "VNET_API_ERROR_VALUE_EXIST: Value already exists")                             \
_(VNET_API_ERROR_SAME_SRC_DST, -82, "VNET_API_ERROR_SAME_SRC_DST: Source and destination are the same")             \
_(VNET_API_ERROR_IP6_MULTICAST_ADDRESS_NOT_PRESENT, -83, "VNET_API_ERROR_IP6_MULTICAST_ADDRESS_NOT_PRESENT: IP6 multicast address required") \
_(VNET_API_ERROR_SR_POLICY_NAME_NOT_PRESENT, -84, "VNET_API_ERROR_SR_POLICY_NAME_NOT_PRESENT: Segment routing policy name required") \
_(VNET_API_ERROR_NOT_RUNNING_AS_ROOT, -85, "VNET_API_ERROR_NOT_RUNNING_AS_ROOT: Not running as root") \
_(VNET_API_ERROR_ALREADY_CONNECTED, -86, "VNET_API_ERROR_ALREADY_CONNECTED: Connection to the data plane already exists") \
_(VNET_API_ERROR_UNSUPPORTED_JNI_VERSION, -87, "VNET_API_ERROR_UNSUPPORTED_JNI_VERSION: Unsupported JNI version") \
_(VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD, -88, "VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD: Failed to attach to Java thread") \
_(VNET_API_ERROR_INVALID_WORKER, -89, "VNET_API_ERROR_INVALID_WORKER: Invalid worker thread")                         \
_(VNET_API_ERROR_LISP_DISABLED, -90, "VNET_API_ERROR_LISP_DISABLED: LISP is disabled")                               \
_(VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND, -91, "VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND: Classify table not found")            \
_(VNET_API_ERROR_INVALID_EID_TYPE, -92, "VNET_API_ERROR_INVALID_EID_TYPE: Unsupported LISP EID type")                   \
_(VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE, -93, "VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE: Cannot create pcap file")              \
_(VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE, -94, "IVNET_API_ERROR_INCORRECT_ADJACENCY_TYPE: nvalid adjacency type for this operation") \
_(VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY, -95, "VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY: Operation would exceed configured capacity of ranges") \
_(VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY, -96, "VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY: Operation would exceed capacity of number of ports") \
_(VNET_API_ERROR_INVALID_ADDRESS_FAMILY, -97, "VNET_API_ERROR_INVALID_ADDRESS_FAMILY: Invalid address family")                \
_(VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX, -98, "VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX: Invalid sub-interface sw_if_index")    \
_(VNET_API_ERROR_TABLE_TOO_BIG, -99, "VNET_API_ERROR_TABLE_TOO_BIG: Table too big")                                  \
_(VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE, -100, "VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE: Cannot enable/disable feature") \
_(VNET_API_ERROR_BFD_EEXIST, -101, "VNET_API_ERROR_BFD_EEXIST: Duplicate BFD object")                             \
_(VNET_API_ERROR_BFD_ENOENT, -102, "VNET_API_ERROR_BFD_ENOENT: No such BFD object")                               \
_(VNET_API_ERROR_BFD_EINUSE, -103, "VNET_API_ERROR_BFD_EINUSE: BFD object in use")                                \
_(VNET_API_ERROR_BFD_NOTSUPP, -104, "VNET_API_ERROR_BFD_NOTSUPP: BFD feature not supported")                       \
_(VNET_API_ERROR_ADDRESS_IN_USE, -105, "VNET_API_ERROR_ADDRESS_IN_USE: Address in use")				\
_(VNET_API_ERROR_ADDRESS_NOT_IN_USE, -106, "VNET_API_ERROR_ADDRESS_NOT_IN_USE: Address not in use")			\
_(VNET_API_ERROR_QUEUE_FULL, -107, "VNET_API_ERROR_QUEUE_FULL: Queue full")                                       \
_(VNET_API_ERROR_APP_UNSUPPORTED_CFG, -108, "VNET_API_ERROR_APP_UNSUPPORTED_CFG: Unsupported application config")		\
_(VNET_API_ERROR_URI_FIFO_CREATE_FAILED, -109, "VNET_API_ERROR_URI_FIFO_CREATE_FAILED: URI FIFO segment create failed")       \
_(VNET_API_ERROR_LISP_RLOC_LOCAL, -110, "VNET_API_ERROR_LISP_RLOC_LOCAL: RLOC address is local")                       \
_(VNET_API_ERROR_BFD_EAGAIN, -111, "VNET_API_ERROR_BFD_EAGAIN: BFD object cannot be manipulated at this time")	\
_(VNET_API_ERROR_INVALID_GPE_MODE, -112, "VNET_API_ERROR_INVALID_GPE_MODE: Invalid GPE mode")                           \
_(VNET_API_ERROR_LISP_GPE_ENTRIES_PRESENT, -113, "VNET_API_ERROR_LISP_GPE_ENTRIES_PRESENT: LISP GPE entries are present")       \
_(VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE, -114, "VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE: Address found for interface")	\
_(VNET_API_ERROR_SESSION_CONNECT, -115, "VNET_API_ERROR_SESSION_CONNECT: Session failed to connect")              	\
_(VNET_API_ERROR_ENTRY_ALREADY_EXISTS, -116, "VNET_API_ERROR_ENTRY_ALREADY_EXISTS: Entry already exists")			\
_(VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL, -117, "VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL: Svm segment create fail")		\
_(VNET_API_ERROR_APPLICATION_NOT_ATTACHED, -118, "VNET_API_ERROR_APPLICATION_NOT_ATTACHED: Application not attached")           \
_(VNET_API_ERROR_BD_ALREADY_EXISTS, -119, "VNET_API_ERROR_BD_ALREADY_EXISTS: Bridge domain already exists")              \
_(VNET_API_ERROR_BD_IN_USE, -120, "VNET_API_ERROR_BD_IN_USE: Bridge domain has member interfaces")		\
_(VNET_API_ERROR_BD_NOT_MODIFIABLE, -121, "VNET_API_ERROR_BD_NOT_MODIFIABLE: Bridge domain 0 can't be deleted/modified") \
_(VNET_API_ERROR_BD_ID_EXCEED_MAX, -122, "VNET_API_ERROR_BD_ID_EXCEED_MAX: Bridge domain ID exceeds 16M limit")		\
_(VNET_API_ERROR_SUBIF_DOESNT_EXIST, -123, "VNET_API_ERROR_SUBIF_DOESNT_EXIST: Subinterface doesn't exist")               \
_(VNET_API_ERROR_L2_MACS_EVENT_CLINET_PRESENT, -124, "VNET_API_ERROR_L2_MACS_EVENT_CLINET_PRESENT: Client already exist for L2 MACs events") \
_(VNET_API_ERROR_INVALID_QUEUE, -125, "VNET_API_ERROR_INVALID_QUEUE: Invalid queue")                 		\
_(VNET_API_ERROR_UNSUPPORTED, -126, "VNET_API_ERROR_UNSUPPORTED: Unsupported")					\
_(VNET_API_ERROR_DUPLICATE_IF_ADDRESS, -127, "VNET_API_ERROR_DUPLICATE_IF_ADDRESS: Address already present on another interface")	\
_(VNET_API_ERROR_APP_INVALID_NS, -128, "VNET_API_ERROR_APP_INVALID_NS: Invalid application namespace")			\
_(VNET_API_ERROR_APP_WRONG_NS_SECRET, -129, "VNET_API_ERROR_APP_WRONG_NS_SECRET: Wrong app namespace secret")		\
_(VNET_API_ERROR_APP_CONNECT_SCOPE, -130, "VNET_API_ERROR_APP_CONNECT_SCOPE: Connect scope")				\
_(VNET_API_ERROR_APP_ALREADY_ATTACHED, -131, "VNET_API_ERROR_APP_ALREADY_ATTACHED: App already attached")			\
_(VNET_API_ERROR_SESSION_REDIRECT, -132, "VNET_API_ERROR_SESSION_REDIRECT: Redirect failed")				\
_(VNET_API_ERROR_ILLEGAL_NAME, -133, "VNET_API_ERROR_ILLEGAL_NAME: Illegal name")					\
_(VNET_API_ERROR_NO_NAME_SERVERS, -134, "VNET_API_ERROR_NO_NAME_SERVERS: No name servers configured")			\
_(VNET_API_ERROR_NAME_SERVER_NOT_FOUND, -135, "VNET_API_ERROR_NAME_SERVER_NOT_FOUND: Name server not found")			\
_(VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED, -136, "VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED: Name resolution not enabled")	\
_(VNET_API_ERROR_NAME_SERVER_FORMAT_ERROR, -137, "VNET_API_ERROR_NAME_SERVER_FORMAT_ERROR: Server format error (bug!)")		\
_(VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME, -138, "VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME: No such name")                       \
_(VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES, -139, "VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES: No addresses available")		\
_(VNET_API_ERROR_NAME_SERVER_NEXT_SERVER, -140, "VNET_API_ERROR_NAME_SERVER_NEXT_SERVER: Retry with new server")		\
_(VNET_API_ERROR_APP_CONNECT_FILTERED, -141, "VNET_API_ERROR_APP_CONNECT_FILTERED: Connect was filtered")			\
_(VNET_API_ERROR_ACL_IN_USE_INBOUND, -142, "VNET_API_ERROR_ACL_IN_USE_INBOUND: Inbound ACL in use")			\
_(VNET_API_ERROR_ACL_IN_USE_OUTBOUND, -143, "VNET_API_ERROR_ACL_IN_USE_OUTBOUND: Outbound ACL in use")			\
_(VNET_API_ERROR_INIT_FAILED, -144, "VNET_API_ERROR_INIT_FAILED: Initialization Failed")				\
_(VNET_API_ERROR_NETLINK_ERROR, -145, "VNET_API_ERROR_NETLINK_ERROR: Netlink error")                                 \
_(VNET_API_ERROR_BIER_BSL_UNSUP, -146, "VNET_API_ERROR_BIER_BSL_UNSUP: BIER bit-string-length unsupported")		\
_(VNET_API_ERROR_INSTANCE_IN_USE, -147, "VNET_API_ERROR_INSTANCE_IN_USE: Instance in use")				\
_(VNET_API_ERROR_INVALID_SESSION_ID, -148, "VNET_API_ERROR_INVALID_SESSION_ID: Session ID out of range")			\
_(VNET_API_ERROR_ACL_IN_USE_BY_LOOKUP_CONTEXT, -149, "VNET_API_ERROR_ACL_IN_USE_BY_LOOKUP_CONTEXT: ACL in use by a lookup context")	\
_(VNET_API_ERROR_INVALID_VALUE_3, -150, "VNET_API_ERROR_INVALID_VALUE_3: Invalid value #3")                            \
_(VNET_API_ERROR_NON_ETHERNET, -151, "VNET_API_ERROR_NON_ETHERNET: Interface is not an Ethernet interface")         \
_(VNET_API_ERROR_BD_ALREADY_HAS_BVI, -152, "VNET_API_ERROR_BD_ALREADY_HAS_BVI: Bridge domain already has a BVI interface") \
_(VNET_API_ERROR_INVALID_PROTOCOL, -153, "VNET_API_ERROR_INVALID_PROTOCOL: Invalid Protocol")                           \
_(VNET_API_ERROR_INVALID_ALGORITHM, -154, "VNET_API_ERROR_INVALID_ALGORITHM: Invalid Algorithm")                         \
_(VNET_API_ERROR_RSRC_IN_USE, -155, "VNET_API_ERROR_RSRC_IN_USE: Resource In Use")                                 \
_(VNET_API_ERROR_KEY_LENGTH, -156, "VNET_API_ERROR_KEY_LENGTH: Invalid Key Length")                               \
_(VNET_API_ERROR_FIB_PATH_UNSUPPORTED_NH_PROTO, -157, "VNET_API_ERROR_FIB_PATH_UNSUPPORTED_NH_PROTO: Unsupported FIB Path protocol")

typedef enum
{
#define _(a,b,c) a = (b),
  foreach_vnet_api_error
#undef _
    VNET_API_N_ERROR,
} vnet_api_error_t;

/* *INDENT-OFF* */
static inline u8 *
format_vnet_api_errno (u8 * s, va_list * args)
{
  vnet_api_error_t api_error = va_arg (*args, vnet_api_error_t);
#ifdef _
#undef _
#endif
#define _(a, b, c)           \
  case b:                    \
    s = format (s, "%s", c); \
    break;
  switch (api_error)
    {
      foreach_vnet_api_error
      default:
       	s = format (s, "UNKNOWN");
        break;
    }
  return s;
#undef _
}
/* *INDENT-ON* */

static const int defined_api_errnos[] =
#ifdef _
#undef _
#endif
#define _(a, b, c) \
  b ,
{ foreach_vnet_api_error };

#undef _
;

#endif /* included_vnet_api_errno_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
