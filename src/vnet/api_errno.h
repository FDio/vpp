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
_(VNET_API_ERROR_UNSPECIFIED, -1, "Unspecified Error", "VNET_API_ERROR_UNSPECIFIED: ")                                 \
_(VNET_API_ERROR_INVALID_SW_IF_INDEX, -2, "Invalid sw_if_index", "VNET_API_ERROR_INVALID_SW_IF_INDEX: ")                       \
_(VNET_API_ERROR_NO_SUCH_FIB, -3, "No such FIB / VRF", "VNET_API_ERROR_NO_SUCH_FIB: ")                                 \
_(VNET_API_ERROR_NO_SUCH_INNER_FIB, -4, "No such inner FIB / VRF", "VNET_API_ERROR_NO_SUCH_INNER_FIB: ")                     \
_(VNET_API_ERROR_NO_SUCH_LABEL, -5, "No such label", "VNET_API_ERROR_NO_SUCH_LABEL: ")                                   \
_(VNET_API_ERROR_NO_SUCH_ENTRY, -6, "No such entry", "VNET_API_ERROR_NO_SUCH_ENTRY: ")                                   \
_(VNET_API_ERROR_INVALID_VALUE, -7, "Invalid value", "VNET_API_ERROR_INVALID_VALUE: ")                                   \
_(VNET_API_ERROR_INVALID_VALUE_2, -8, "Invalid value #2", "VNET_API_ERROR_INVALID_VALUE_2: ")                              \
_(VNET_API_ERROR_UNIMPLEMENTED, -9, "Unimplemented", "VNET_API_ERROR_UNIMPLEMENTED: ")                                   \
_(VNET_API_ERROR_INVALID_SW_IF_INDEX_2, -10, "Invalid sw_if_index #2", "VNET_API_ERROR_INVALID_SW_IF_INDEX_2: ")                 \
_(VNET_API_ERROR_SYSCALL_ERROR_1, -11, "System call error #1", "VNET_API_ERROR_SYSCALL_ERROR_1: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_2, -12, "System call error #2", "VNET_API_ERROR_SYSCALL_ERROR_2: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_3, -13, "System call error #3", "VNET_API_ERROR_SYSCALL_ERROR_3: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_4, -14, "System call error #4", "VNET_API_ERROR_SYSCALL_ERROR_4: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_5, -15, "System call error #5", "VNET_API_ERROR_SYSCALL_ERROR_5: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_6, -16, "System call error #6", "VNET_API_ERROR_SYSCALL_ERROR_6: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_7, -17, "System call error #7", "VNET_API_ERROR_SYSCALL_ERROR_7: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_8, -18, "System call error #8", "VNET_API_ERROR_SYSCALL_ERROR_8: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_9, -19, "System call error #9", "VNET_API_ERROR_SYSCALL_ERROR_9: ")                         \
_(VNET_API_ERROR_SYSCALL_ERROR_10, -20, "System call error #10", "VNET_API_ERROR_SYSCALL_ERROR_10: ")                       \
_(VNET_API_ERROR_FEATURE_DISABLED, -30, "Feature disabled by configuration", "VNET_API_ERROR_FEATURE_DISABLED: ")           \
_(VNET_API_ERROR_INVALID_REGISTRATION, -31, "Invalid registration", "VNET_API_ERROR_INVALID_REGISTRATION: ")                    \
_(VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB, -50, "Next hop not in FIB", "VNET_API_ERROR_NEXT_HOP_NOT_IN_FIB: ")                      \
_(VNET_API_ERROR_UNKNOWN_DESTINATION, -51, "Unknown destination", "VNET_API_ERROR_UNKNOWN_DESTINATION: ")                      \
_(VNET_API_ERROR_NO_PATHS_IN_ROUTE, -52, "No paths specified in route", "VNET_API_ERROR_NO_PATHS_IN_ROUTE: ")                \
_(VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP, -53, "Next hop not found (multipath)", "VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP: ")         \
_(VNET_API_ERROR_NO_MATCHING_INTERFACE, -54, "No matching interface for probe", "VNET_API_ERROR_NO_MATCHING_INTERFACE: ")        \
_(VNET_API_ERROR_INVALID_VLAN, -55, "Invalid VLAN", "VNET_API_ERROR_INVALID_VLAN: ")                                    \
_(VNET_API_ERROR_VLAN_ALREADY_EXISTS, -56, "VLAN subif already exists", "VNET_API_ERROR_VLAN_ALREADY_EXISTS: ")                \
_(VNET_API_ERROR_INVALID_SRC_ADDRESS, -57, "Invalid src address", "VNET_API_ERROR_INVALID_SRC_ADDRESS: ")                      \
_(VNET_API_ERROR_INVALID_DST_ADDRESS, -58, "Invalid dst address", "VNET_API_ERROR_INVALID_DST_ADDRESS: ")                      \
_(VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH, -59, "Address length mismatch", "VNET_API_ERROR_ADDRESS_LENGTH_MISMATCH: ")              \
_(VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE, -60, "Address not found for interface", "VNET_API_ERROR_ADDRESS_NOT_FOUND_FOR_INTERFACE: ") \
_(VNET_API_ERROR_ADDRESS_NOT_DELETABLE, -61, "Address not deletable", "VNET_API_ERROR_ADDRESS_NOT_DELETABLE: ")                  \
_(VNET_API_ERROR_IP6_NOT_ENABLED, -62, "ip6 not enabled", "VNET_API_ERROR_IP6_NOT_ENABLED: ")				\
_(VNET_API_ERROR_NO_SUCH_NODE, -63, "No such graph node", "VNET_API_ERROR_NO_SUCH_NODE: ")				\
_(VNET_API_ERROR_NO_SUCH_NODE2, -64, "No such graph node #2", "VNET_API_ERROR_NO_SUCH_NODE2: ")				\
_(VNET_API_ERROR_NO_SUCH_TABLE, -65, "No such table", "VNET_API_ERROR_NO_SUCH_TABLE: ")                                  \
_(VNET_API_ERROR_NO_SUCH_TABLE2, -66, "No such table #2", "VNET_API_ERROR_NO_SUCH_TABLE2: ")                              \
_(VNET_API_ERROR_NO_SUCH_TABLE3, -67, "No such table #3", "VNET_API_ERROR_NO_SUCH_TABLE3: ")                              \
_(VNET_API_ERROR_SUBIF_ALREADY_EXISTS, -68, "Subinterface already exists", "VNET_API_ERROR_SUBIF_ALREADY_EXISTS: ")             \
_(VNET_API_ERROR_SUBIF_CREATE_FAILED, -69, "Subinterface creation failed", "VNET_API_ERROR_SUBIF_CREATE_FAILED: ")		\
_(VNET_API_ERROR_INVALID_MEMORY_SIZE, -70, "Invalid memory size requested", "VNET_API_ERROR_INVALID_MEMORY_SIZE: ")            \
_(VNET_API_ERROR_INVALID_INTERFACE, -71, "Invalid interface", "VNET_API_ERROR_INVALID_INTERFACE: ")                          \
_(VNET_API_ERROR_INVALID_VLAN_TAG_COUNT, -72, "Invalid number of tags for requested operation", "VNET_API_ERROR_INVALID_VLAN_TAG_COUNT: ") \
_(VNET_API_ERROR_INVALID_ARGUMENT, -73, "Invalid argument", "VNET_API_ERROR_INVALID_ARGUMENT: ")                            \
_(VNET_API_ERROR_UNEXPECTED_INTF_STATE, -74, "Unexpected interface state", "VNET_API_ERROR_UNEXPECTED_INTF_STATE: ")             \
_(VNET_API_ERROR_TUNNEL_EXIST, -75, "Tunnel already exists", "VNET_API_ERROR_TUNNEL_EXIST: ")                           \
_(VNET_API_ERROR_INVALID_DECAP_NEXT, -76, "Invalid decap-next", "VNET_API_ERROR_INVALID_DECAP_NEXT: ")			\
_(VNET_API_ERROR_RESPONSE_NOT_READY, -77, "Response not ready", "VNET_API_ERROR_RESPONSE_NOT_READY: ")			\
_(VNET_API_ERROR_NOT_CONNECTED, -78, "Not connected to the data plane", "VNET_API_ERROR_NOT_CONNECTED: ")                \
_(VNET_API_ERROR_IF_ALREADY_EXISTS, -79, "Interface already exists", "VNET_API_ERROR_IF_ALREADY_EXISTS: ")                   \
_(VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED, -80, "Operation not allowed on slave of BondEthernet", "VNET_API_ERROR_BOND_SLAVE_NOT_ALLOWED: ") \
_(VNET_API_ERROR_VALUE_EXIST, -81, "Value already exists", "VNET_API_ERROR_VALUE_EXIST: ")                             \
_(VNET_API_ERROR_SAME_SRC_DST, -82, "Source and destination are the same", "VNET_API_ERROR_SAME_SRC_DST: ")             \
_(VNET_API_ERROR_IP6_MULTICAST_ADDRESS_NOT_PRESENT, -83, "IP6 multicast address required", "VNET_API_ERROR_IP6_MULTICAST_ADDRESS_NOT_PRESENT: ") \
_(VNET_API_ERROR_SR_POLICY_NAME_NOT_PRESENT, -84, "Segment routing policy name required", "VNET_API_ERROR_SR_POLICY_NAME_NOT_PRESENT: ") \
_(VNET_API_ERROR_NOT_RUNNING_AS_ROOT, -85, "Not running as root", "VNET_API_ERROR_NOT_RUNNING_AS_ROOT: ") \
_(VNET_API_ERROR_ALREADY_CONNECTED, -86, "Connection to the data plane already exists", "VNET_API_ERROR_ALREADY_CONNECTED: ") \
_(VNET_API_ERROR_UNSUPPORTED_JNI_VERSION, -87, "Unsupported JNI version", "VNET_API_ERROR_UNSUPPORTED_JNI_VERSION: ") \
_(VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD, -88, "Failed to attach to Java thread", "VNET_API_ERROR_FAILED_TO_ATTACH_TO_JAVA_THREAD: ") \
_(VNET_API_ERROR_INVALID_WORKER, -89, "Invalid worker thread", "VNET_API_ERROR_INVALID_WORKER: ")                         \
_(VNET_API_ERROR_LISP_DISABLED, -90, "LISP is disabled", "VNET_API_ERROR_LISP_DISABLED: ")                               \
_(VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND, -91, "Classify table not found", "VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND: ")            \
_(VNET_API_ERROR_INVALID_EID_TYPE, -92, "Unsupported LISP EID type", "VNET_API_ERROR_INVALID_EID_TYPE: ")                   \
_(VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE, -93, "Cannot create pcap file", "VNET_API_ERROR_CANNOT_CREATE_PCAP_FILE: ")              \
_(VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE, -94, "Invalid adjacency type for this operation", "VNET_API_ERROR_INCORRECT_ADJACENCY_TYPE: ") \
_(VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY, -95, "Operation would exceed configured capacity of ranges", "VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY: ") \
_(VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY, -96, "Operation would exceed capacity of number of ports", "VNET_API_ERROR_EXCEEDED_NUMBER_OF_PORTS_CAPACITY: ") \
_(VNET_API_ERROR_INVALID_ADDRESS_FAMILY, -97, "Invalid address family", "VNET_API_ERROR_INVALID_ADDRESS_FAMILY: ")                \
_(VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX, -98, "Invalid sub-interface sw_if_index", "VNET_API_ERROR_INVALID_SUB_SW_IF_INDEX: ")    \
_(VNET_API_ERROR_TABLE_TOO_BIG, -99, "Table too big", "VNET_API_ERROR_TABLE_TOO_BIG: ")                                  \
_(VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE, -100, "Cannot enable/disable feature", "VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE: ") \
_(VNET_API_ERROR_BFD_EEXIST, -101, "Duplicate BFD object", "VNET_API_ERROR_BFD_EEXIST: ")                             \
_(VNET_API_ERROR_BFD_ENOENT, -102, "No such BFD object", "VNET_API_ERROR_BFD_ENOENT: ")                               \
_(VNET_API_ERROR_BFD_EINUSE, -103, "VNET_API_ERROR_BFD_EINUSE: BFD object in use", "VNET_API_ERROR_BFD_EINUSE: ")                                \
_(VNET_API_ERROR_BFD_NOTSUPP, -104, "BFD feature not supported", "VNET_API_ERROR_BFD_NOTSUPP: ")                       \
_(VNET_API_ERROR_ADDRESS_IN_USE, -105, "Address in use", "VNET_API_ERROR_ADDRESS_IN_USE: ")				\
_(VNET_API_ERROR_ADDRESS_NOT_IN_USE, -106, "Address not in use", "VNET_API_ERROR_ADDRESS_NOT_IN_USE: ")			\
_(VNET_API_ERROR_QUEUE_FULL, -107, "Queue full", "VNET_API_ERROR_QUEUE_FULL: ")                                       \
_(VNET_API_ERROR_APP_UNSUPPORTED_CFG, -108, "Unsupported application config", "VNET_API_ERROR_APP_UNSUPPORTED_CFG: ")		\
_(VNET_API_ERROR_URI_FIFO_CREATE_FAILED, -109, "URI FIFO segment create failed", "VNET_API_ERROR_URI_FIFO_CREATE_FAILED: ")       \
_(VNET_API_ERROR_LISP_RLOC_LOCAL, -110, "RLOC address is local", "VNET_API_ERROR_LISP_RLOC_LOCAL: ")                       \
_(VNET_API_ERROR_BFD_EAGAIN, -111, "BFD object cannot be manipulated at this time", "VNET_API_ERROR_BFD_EAGAIN: ")	\
_(VNET_API_ERROR_INVALID_GPE_MODE, -112, "Invalid GPE mode", "VNET_API_ERROR_INVALID_GPE_MODE: ")                           \
_(VNET_API_ERROR_LISP_GPE_ENTRIES_PRESENT, -113, "LISP GPE entries are present", "VNET_API_ERROR_LISP_GPE_ENTRIES_PRESENT: ")       \
_(VNET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE, -114, "VAddress found for interface", "NET_API_ERROR_ADDRESS_FOUND_FOR_INTERFACE: ")	\
_(VNET_API_ERROR_SESSION_CONNECT, -115, "Session failed to connect", "VNET_API_ERROR_SESSION_CONNECT: ")              	\
_(VNET_API_ERROR_ENTRY_ALREADY_EXISTS, -116, "Entry already exists", "VNET_API_ERROR_ENTRY_ALREADY_EXISTS: ")			\
_(VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL, -117, "Svm segment create fail", "VNET_API_ERROR_SVM_SEGMENT_CREATE_FAIL: ")		\
_(VNET_API_ERROR_APPLICATION_NOT_ATTACHED, -118, "Application not attached", "VNET_API_ERROR_APPLICATION_NOT_ATTACHED: ")           \
_(VNET_API_ERROR_BD_ALREADY_EXISTS, -119, "Bridge domain already exists", "VNET_API_ERROR_BD_ALREADY_EXISTS: ")              \
_(VNET_API_ERROR_BD_IN_USE, -120, "Bridge domain has member interfaces", "VNET_API_ERROR_BD_IN_USE: ")		\
_(VNET_API_ERROR_BD_NOT_MODIFIABLE, -121, "Bridge domain 0 can't be deleted/modified", "VNET_API_ERROR_BD_NOT_MODIFIABLE: ") \
_(VNET_API_ERROR_BD_ID_EXCEED_MAX, -122, "Bridge domain ID exceeds 16M limit", "VNET_API_ERROR_BD_ID_EXCEED_MAX: ")		\
_(VNET_API_ERROR_SUBIF_DOESNT_EXIST, -123, "Subinterface doesn't exist", "VNET_API_ERROR_SUBIF_DOESNT_EXIST: ")               \
_(VNET_API_ERROR_L2_MACS_EVENT_CLINET_PRESENT, -124, "Client already exist for L2 MACs events", "VNET_API_ERROR_L2_MACS_EVENT_CLINET_PRESENT: ") \
_(VNET_API_ERROR_INVALID_QUEUE, -125, "Invalid queue", "VNET_API_ERROR_INVALID_QUEUE: ")                 		\
_(VNET_API_ERROR_UNSUPPORTED, -126, "Unsupported", "VNET_API_ERROR_UNSUPPORTED: ")					\
_(VNET_API_ERROR_DUPLICATE_IF_ADDRESS, -127, "Address already present on another interface", "VNET_API_ERROR_DUPLICATE_IF_ADDRESS: ")	\
_(VNET_API_ERROR_APP_INVALID_NS, -128, "Invalid application namespace", "VNET_API_ERROR_APP_INVALID_NS: ")			\
_(VNET_API_ERROR_APP_WRONG_NS_SECRET, -129, "Wrong app namespace secret", "VNET_API_ERROR_APP_WRONG_NS_SECRET: ")		\
_(VNET_API_ERROR_APP_CONNECT_SCOPE, -130, "Connect scope", "VNET_API_ERROR_APP_CONNECT_SCOPE: ")				\
_(VNET_API_ERROR_APP_ALREADY_ATTACHED, -131, "App already attached", "VNET_API_ERROR_APP_ALREADY_ATTACHED: ")			\
_(VNET_API_ERROR_SESSION_REDIRECT, -132, "Redirect failed", "VNET_API_ERROR_SESSION_REDIRECT: ")				\
_(VNET_API_ERROR_ILLEGAL_NAME, -133, "Illegal name", "VNET_API_ERROR_ILLEGAL_NAME: ")					\
_(VNET_API_ERROR_NO_NAME_SERVERS, -134, "No name servers configured", "VNET_API_ERROR_NO_NAME_SERVERS: ")			\
_(VNET_API_ERROR_NAME_SERVER_NOT_FOUND, -135, "Name server not found", "VNET_API_ERROR_NAME_SERVER_NOT_FOUND: ")			\
_(VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED, -136, "Name resolution not enabled", "VNET_API_ERROR_NAME_RESOLUTION_NOT_ENABLED: ")	\
_(VNET_API_ERROR_NAME_SERVER_FORMAT_ERROR, -137, "Server format error (bug!)", "VNET_API_ERROR_NAME_SERVER_FORMAT_ERROR: ")		\
_(VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME, -138, "No such name", "VNET_API_ERROR_NAME_SERVER_NO_SUCH_NAME: ")                       \
_(VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES, -139, "No addresses available", "VNET_API_ERROR_NAME_SERVER_NO_ADDRESSES: ")		\
_(VNET_API_ERROR_NAME_SERVER_NEXT_SERVER, -140, "Retry with new server", "VNET_API_ERROR_NAME_SERVER_NEXT_SERVER: ")		\
_(VNET_API_ERROR_APP_CONNECT_FILTERED, -141, "Connect was filtered", "VNET_API_ERROR_APP_CONNECT_FILTERED: ")			\
_(VNET_API_ERROR_ACL_IN_USE_INBOUND, -142, "Inbound ACL in use", "VNET_API_ERROR_ACL_IN_USE_INBOUND: ")			\
_(VNET_API_ERROR_ACL_IN_USE_OUTBOUND, -143, "Outbound ACL in use", "VNET_API_ERROR_ACL_IN_USE_OUTBOUND: ")			\
_(VNET_API_ERROR_INIT_FAILED, -144, "Initialization Failed", "VNET_API_ERROR_INIT_FAILED: ")				\
_(VNET_API_ERROR_NETLINK_ERROR, -145, "Netlink error", "VNET_API_ERROR_NETLINK_ERROR: ")                                 \
_(VNET_API_ERROR_BIER_BSL_UNSUP, -146, "BIER bit-string-length unsupported", "VNET_API_ERROR_BIER_BSL_UNSUP: ")		\
_(VNET_API_ERROR_INSTANCE_IN_USE, -147, "Instance in use", "VNET_API_ERROR_INSTANCE_IN_USE: ")				\
_(VNET_API_ERROR_INVALID_SESSION_ID, -148, "Session ID out of range", "VNET_API_ERROR_INVALID_SESSION_ID: ")			\
_(VNET_API_ERROR_ACL_IN_USE_BY_LOOKUP_CONTEXT, -149, "VNET_API_ERROR_ACL_IN_USE_BY_LOOKUP_CONTEXT: ACL in use by a lookup context", "")	\
_(VNET_API_ERROR_INVALID_VALUE_3, -150, "Invalid value #3", "VNET_API_ERROR_INVALID_VALUE_3: ")                            \
_(VNET_API_ERROR_NON_ETHERNET, -151, "Interface is not an Ethernet interface", "VNET_API_ERROR_NON_ETHERNET: ")         \
_(VNET_API_ERROR_BD_ALREADY_HAS_BVI, -152, "Bridge domain already has a BVI interface", "VNET_API_ERROR_BD_ALREADY_HAS_BVI: ") \
_(VNET_API_ERROR_INVALID_PROTOCOL, -153, "Invalid Protocol", "VNET_API_ERROR_INVALID_PROTOCOL: ")                           \
_(VNET_API_ERROR_INVALID_ALGORITHM, -154, "Invalid Algorithm", "VNET_API_ERROR_INVALID_ALGORITHM: ")                         \
_(VNET_API_ERROR_RSRC_IN_USE, -155, "Resource In Use", "VNET_API_ERROR_RSRC_IN_USE: ")                                 \
_(VNET_API_ERROR_KEY_LENGTH, -156, "Invalid Key Length", "VNET_API_ERROR_KEY_LENGTH: ")                               \
_(VNET_API_ERROR_FIB_PATH_UNSUPPORTED_NH_PROTO, -157, "Unsupported FIB Path protocol", "VNET_API_ERROR_FIB_PATH_UNSUPPORTED_NH_PROTO: ") \
_(VNET_API_ERROR_API_ENDIAN_FAILED, -159, "Endian mismatch detected", "VNET_API_ERROR_API_ENDIAN_FAILED: ") \

typedef enum
{
#define _(a,b,c,d) a = (b),
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
#define _(a, b, c, d)           \
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

#endif /* included_vnet_api_errno_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
