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

#define foreach_vnet_api_error						\
_(UNSPECIFIED, -1, "Unspecified Error")                                 \
_(INVALID_SW_IF_INDEX, -2, "Invalid sw_if_index")                       \
_(NO_SUCH_FIB, -3, "No such FIB / VRF")                                 \
_(NO_SUCH_INNER_FIB, -4, "No such inner FIB / VRF")                     \
_(NO_SUCH_LABEL, -5, "No such label")                                   \
_(NO_SUCH_ENTRY, -6, "No such entry")                                   \
_(INVALID_VALUE, -7, "Invalid value")                                   \
_(INVALID_VALUE_2, -8, "Invalid value #2")                              \
_(UNIMPLEMENTED, -9, "Unimplemented")                                   \
_(INVALID_SW_IF_INDEX_2, -10, "Invalid sw_if_index #2")                 \
_(SYSCALL_ERROR_1, -11, "System call error #1")                         \
_(SYSCALL_ERROR_2, -12, "System call error #2")                         \
_(SYSCALL_ERROR_3, -13, "System call error #3")                         \
_(SYSCALL_ERROR_4, -14, "System call error #4")                         \
_(SYSCALL_ERROR_5, -15, "System call error #5")                         \
_(SYSCALL_ERROR_6, -16, "System call error #6")                         \
_(SYSCALL_ERROR_7, -17, "System call error #7")                         \
_(SYSCALL_ERROR_8, -18, "System call error #8")                         \
_(SYSCALL_ERROR_9, -19, "System call error #9")                         \
_(SYSCALL_ERROR_10, -20, "System call error #9")                        \
_(FEATURE_DISABLED, -30, "Feature disabled by configuration")           \
_(INVALID_REGISTRATION, -31, "Invalid registration")                    \
_(NEXT_HOP_NOT_IN_FIB, -50, "Next hop not in FIB")                      \
_(UNKNOWN_DESTINATION, -51, "Unknown destination")                      \
_(PREFIX_MATCHES_NEXT_HOP, -52, "Prefix matches next hop")              \
_(NEXT_HOP_NOT_FOUND_MP, -53, "Next hop not found (multipath)")         \
_(NO_MATCHING_INTERFACE, -54, "No matching interface for probe")        \
_(INVALID_VLAN, -55, "Invalid VLAN")                                    \
_(VLAN_ALREADY_EXISTS, -56, "VLAN subif already exists")                \
_(INVALID_SRC_ADDRESS, -57, "Invalid src address")                      \
_(INVALID_DST_ADDRESS, -58, "Invalid dst address")                      \
_(ADDRESS_LENGTH_MISMATCH, -59, "Address length mismatch")              \
_(ADDRESS_NOT_FOUND_FOR_INTERFACE, -60, "Address not found for interface") \
_(ADDRESS_NOT_LINK_LOCAL, -61, "Address not link-local")                \
_(IP6_NOT_ENABLED, -62, "ip6 not enabled")				\
_(ADDRESS_MATCHES_INTERFACE_ADDRESS, -63, "Address matches interface address") \
_(IN_PROGRESS, 10, "Operation in progress")				\
_(NO_SUCH_NODE, -63, "No such graph node")				\
_(NO_SUCH_NODE2, -64, "No such graph node #2")				\
_(NO_SUCH_TABLE, -65, "No such table")                                  \
_(NO_SUCH_TABLE2, -66, "No such table #2")                              \
_(NO_SUCH_TABLE3, -67, "No such table #3")                              \
_(SUBIF_ALREADY_EXISTS, -68, "Subinterface already exists")             \
_(SUBIF_CREATE_FAILED, -69, "Subinterface creation failed")		\
_(INVALID_MEMORY_SIZE, -70, "Invalid memory size requested")            \
_(INVALID_INTERFACE, -71, "Invalid interface")                          \
_(INVALID_VLAN_TAG_COUNT, -72, "Invalid number of tags for requested operation") \
_(INVALID_ARGUMENT, -73, "Invalid argument")                            \
_(UNEXPECTED_INTF_STATE, -74, "Unexpected interface state")             \
_(TUNNEL_EXIST, -75, "Tunnel already exists")                           \
_(INVALID_DECAP_NEXT, -76, "Invalid decap-next")			\
_(RESPONSE_NOT_READY, -77, "Response not ready")			\
_(NOT_CONNECTED, -78, "Not connected to the data plane")                \
_(IF_ALREADY_EXISTS, -79, "Interface already exists")                   \
_(BOND_SLAVE_NOT_ALLOWED, -80, "Operation not allowed on slave of BondEthernet") \
_(VALUE_EXIST, -81, "Value already exists")                             \
_(SAME_SRC_DST, -82, "Source and destination are the same")             \
_(IP6_MULTICAST_ADDRESS_NOT_PRESENT, -83, "IP6 multicast address required") \
_(SR_POLICY_NAME_NOT_PRESENT, -84, "Segement routing policy name required") \
_(NOT_RUNNING_AS_ROOT, -85, "Not running as root") \
_(ALREADY_CONNECTED, -86, "Connection to the data plane already exists") \
_(UNSUPPORTED_JNI_VERSION, -87, "Unsupported JNI version") \
_(FAILED_TO_ATTACH_TO_JAVA_THREAD, -88, "Failed to attach to Java thread") \
_(INVALID_WORKER, -89, "Invalid worker thread")                         \
_(LISP_DISABLED, -90, "LISP is disabled")                               \
_(CLASSIFY_TABLE_NOT_FOUND, -91, "Classify table not found")            \
_(INVALID_EID_TYPE, -92, "Unsupported LSIP EID type")                   \
_(CANNOT_CREATE_PCAP_FILE, -93, "Cannot create pcap file")              \
_(INCORRECT_ADJACENCY_TYPE, -94, "Invalid adjacency type for this operation") \
_(EXCEEDED_NUMBER_OF_RANGES_CAPACITY, -95, "Operation would exceed configured capacity of ranges") \
_(EXCEEDED_NUMBER_OF_PORTS_CAPACITY, -96, "Operation would exceed capacity of number of ports") \
_(INVALID_ADDRESS_FAMILY, -97, "Invalid address family")                \
_(INVALID_SUB_SW_IF_INDEX, -98, "Invalid sub-interface sw_if_index")    \
_(TABLE_TOO_BIG, -99, "Table too big")                                  \
_(CANNOT_ENABLE_DISABLE_FEATURE, -100, "Cannot enable/disable feature") \
_(BFD_EEXIST, -101, "Duplicate BFD session") \
_(BFD_NOENT, -102, "No such BFD session")

typedef enum
{
#define _(a,b,c) VNET_API_ERROR_##a = (b),
  foreach_vnet_api_error
#undef _
    VNET_API_N_ERROR,
} vnet_api_error_t;

#endif /* included_vnet_api_errno_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
