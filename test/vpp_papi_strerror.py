#  Copyright (c) 2019. Vinci Consulting Corp. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


raw_retvals = r"""
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
_(SYSCALL_ERROR_10, -20, "System call error #10")                       \
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
_(ADDRESS_NOT_DELETABLE, -61, "Address not deletable")                  \
_(IP6_NOT_ENABLED, -62, "ip6 not enabled")				\
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
_(BFD_EEXIST, -101, "Duplicate BFD object")                             \
_(BFD_ENOENT, -102, "No such BFD object")                               \
_(BFD_EINUSE, -103, "BFD object in use")                                \
_(BFD_NOTSUPP, -104, "BFD feature not supported")                       \
_(ADDRESS_IN_USE, -105, "Address in use")				\
_(ADDRESS_NOT_IN_USE, -106, "Address not in use")			\
_(QUEUE_FULL, -107, "Queue full")                                       \
_(APP_UNSUPPORTED_CFG, -108, "Unsupported application config")		\
_(URI_FIFO_CREATE_FAILED, -109, "URI FIFO segment create failed")       \
_(LISP_RLOC_LOCAL, -110, "RLOC address is local")                       \
_(BFD_EAGAIN, -111, "BFD object cannot be manipulated at this time")	\
_(INVALID_GPE_MODE, -112, "Invalid GPE mode")                           \
_(LISP_GPE_ENTRIES_PRESENT, -113, "LISP GPE entries are present")       \
_(ADDRESS_FOUND_FOR_INTERFACE, -114, "Address found for interface")	\
_(SESSION_CONNECT, -115, "Session failed to connect")              	\
_(ENTRY_ALREADY_EXISTS, -116, "Entry already exists")			\
_(SVM_SEGMENT_CREATE_FAIL, -117, "svm segment create fail")		\
_(APPLICATION_NOT_ATTACHED, -118, "application not attached")           \
_(BD_ALREADY_EXISTS, -119, "Bridge domain already exists")              \
_(BD_IN_USE, -120, "Bridge domain has member interfaces")		\
_(BD_NOT_MODIFIABLE, -121, "Bridge domain 0 can't be deleted/modified") \
_(BD_ID_EXCEED_MAX, -122, "Bridge domain ID exceed 16M limit")		\
_(SUBIF_DOESNT_EXIST, -123, "Subinterface doesn't exist")               \
_(L2_MACS_EVENT_CLINET_PRESENT, -124, "Client already exist for L2 MACs events") \
_(INVALID_QUEUE, -125, "Invalid queue")                 		\
_(UNSUPPORTED, -126, "Unsupported")					\
_(DUPLICATE_IF_ADDRESS, -127, "Address already present on another interface")	\
_(APP_INVALID_NS, -128, "Invalid application namespace")			\
_(APP_WRONG_NS_SECRET, -129, "Wrong app namespace secret")		\
_(APP_CONNECT_SCOPE, -130, "Connect scope")				\
_(APP_ALREADY_ATTACHED, -131, "App already attached")			\
_(SESSION_REDIRECT, -132, "Redirect failed")				\
_(ILLEGAL_NAME, -133, "Illegal name")					\
_(NO_NAME_SERVERS, -134, "No name servers configured")			\
_(NAME_SERVER_NOT_FOUND, -135, "Name server not found")			\
_(NAME_RESOLUTION_NOT_ENABLED, -136, "Name resolution not enabled")	\
_(NAME_SERVER_FORMAT_ERROR, -137, "Server format error (bug!)")		\
_(NAME_SERVER_NO_SUCH_NAME, -138, "No such name")                       \
_(NAME_SERVER_NO_ADDRESSES, -139, "No addresses available")		\
_(NAME_SERVER_NEXT_SERVER, -140, "Retry with new server")		\
_(APP_CONNECT_FILTERED, -141, "Connect was filtered")			\
_(ACL_IN_USE_INBOUND, -142, "Inbound ACL in use")			\
_(ACL_IN_USE_OUTBOUND, -143, "Outbound ACL in use")			\
_(INIT_FAILED, -144, "Initialization Failed")				\
_(NETLINK_ERROR, -145, "netlink error")                                 \
_(BIER_BSL_UNSUP, -146, "BIER bit-string-length unsupported")		\
_(INSTANCE_IN_USE, -147, "Instance in use")				\
_(INVALID_SESSION_ID, -148, "session ID out of range")			\
_(ACL_IN_USE_BY_LOOKUP_CONTEXT, -149, "ACL in use by a lookup context")	\
_(INVALID_VALUE_3, -150, "Invalid value #3")                            \
_(NON_ETHERNET, -151, "Interface is not an Ethernet interface")         \
_(BD_ALREADY_HAS_BVI, -152, "Bridge domain already has a BVI interface")
""".replace('\t', '').replace('\\', '')  # noqa

lookup = {}
for line in raw_retvals.splitlines():
    line = line.rstrip().rstrip(')').lstrip('_(')
    if ',' in line:
        _, field2, field3 = line.split(',')
        lookup[int(field2)] = field3.replace('"', '').strip()


def strerror(key):
    if key == 0:
        return "No error"
    try:
        return lookup[key]
    except KeyError:
        return "Unknown errno: %s" % key
