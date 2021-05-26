/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief NAT syslog logging constants
 */
#ifndef __included_nat_syslog_constants_h__
#define __included_nat_syslog_constants_h__

#define NAT_FACILITY SYSLOG_FACILITY_LOCAL0

#define NAT_APPNAME "NAT"

#define SADD_SDEL_SEVERITY     SYSLOG_SEVERITY_INFORMATIONAL
#define APMADD_APMDEL_SEVERITY SYSLOG_SEVERITY_INFORMATIONAL

#define SADD_MSGID   "SADD"
#define SDEL_MSGID   "SDEL"
#define APMADD_MSGID "APMADD"
#define APMDEL_MSGID "APMDEL"

#define NSESS_SDID  "nsess"
#define NAPMAP_SDID "napmap"

#define SSUBIX_SDPARAM_NAME "SSUBIX"
#define SVLAN_SDPARAM_NAME  "SVLAN"
#define IATYP_SDPARAM_NAME  "IATYP"
#define ISADDR_SDPARAM_NAME "ISADDR"
#define ISPORT_SDPARAM_NAME "ISPORT"
#define IDADDR_SDPARAM_NAME "IDADDR"
#define IDPORT_SDPARAM_NAME "IDPORT"
#define XATYP_SDPARAM_NAME  "XATYP"
#define XSADDR_SDPARAM_NAME "XSADDR"
#define XSPORT_SDPARAM_NAME "XSPORT"
#define XDADDR_SDPARAM_NAME "XDADDR"
#define XDPORT_SDPARAM_NAME "XDPORT"
#define PROTO_SDPARAM_NAME  "PROTO"
#define SV6ENC_SDPARAM_NAME "SV6ENC"

#define IATYP_IPV4 "IPv4"
#define IATYP_IPV6 "IPv6"

#endif /* __included_nat_syslog_constants_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
