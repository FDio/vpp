/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __PROCESS_CAPABILITIES_H__
#define __PROCESS_CAPABILITIES_H__

#include <vppinfra/types.h>

#define CAPABILITY_VERSION_3 0x20080522
#define CAPABILITY_U32S_3    2

typedef struct _user_cap_header
{
  u32 version;
  int pid;
} cap_user_header_t;

typedef struct _user_cap_data
{
  u64 effective;
  u64 permitted;
  u64 inheritable;
} cap_user_data_t;

#define foreach_process_capabilities                                          \
  _ (CAP_CHOWN, 0, "cap-chown")                                               \
  _ (CAP_DAC_OVERRIDE, 1, "cap-dac-override")                                 \
  _ (CAP_DAC_READ_SEARCH, 2, "cap-dac-read-search")                           \
  _ (CAP_FOWNER, 3, "cap-fowner")                                             \
  _ (CAP_FSETID, 4, "cap-fsetid")                                             \
  _ (CAP_KILL, 5, "cap-kill")                                                 \
  _ (CAP_SETGID, 6, "cap-setgid")                                             \
  _ (CAP_SETUID, 7, "cap-setuid")                                             \
  _ (CAP_SETPCAP, 8, "cap-setpcap")                                           \
  _ (CAP_LINUX_IMMUTABLE, 9, "cap-linux-immutable")                           \
  _ (CAP_NET_BIND_SERVICE, 10, "cap-net-bind-service")                        \
  _ (CAP_NET_BROADCAST, 11, "cap-net-broadcast")                              \
  _ (CAP_NET_ADMIN, 12, "cap-net-admin")                                      \
  _ (CAP_NET_RAW, 13, "cap-net-raw")                                          \
  _ (CAP_IPC_LOCK, 14, "cap-ipc-lock")                                        \
  _ (CAP_IPC_OWNER, 15, "cap-ipc-owner")                                      \
  _ (CAP_SYS_MODULE, 16, "cap-sys-module")                                    \
  _ (CAP_SYS_RAWIO, 17, "cap-sys-rawio")                                      \
  _ (CAP_SYS_CHROOT, 18, "cap-sys-chroot")                                    \
  _ (CAP_SYS_PTRACE, 19, "cap-sys-ptrace")                                    \
  _ (CAP_SYS_PACCT, 20, "cap-sys-pacct")                                      \
  _ (CAP_SYS_ADMIN, 21, "cap-sys-admin")                                      \
  _ (CAP_SYS_BOOT, 22, "cap-sys-boot")                                        \
  _ (CAP_SYS_NICE, 23, "cap-sys-nice")                                        \
  _ (CAP_SYS_RESOURCE, 24, "cap-sys-resource")                                \
  _ (CAP_SYS_TIME, 25, "cap-sys-time")                                        \
  _ (CAP_SYS_TTY_CONFIG, 26, "cap-sys-tty-config")                            \
  _ (CAP_MKNOD, 27, "cap-mknod")                                              \
  _ (CAP_LEASE, 28, "cap-lease")                                              \
  _ (CAP_AUDIT_WRITE, 29, "cap-audit-write")                                  \
  _ (CAP_AUDIT_CONTROL, 30, "cap-audit-control")                              \
  _ (CAP_SETFCAP, 31, "cap-setfcap")                                          \
  _ (CAP_MAC_OVERRIDE, 32, "cap-mac-override")                                \
  _ (CAP_MAC_ADMIN, 33, "cap-mac-admin")                                      \
  _ (CAP_SYSLOG, 34, "cap-syslog")                                            \
  _ (CAP_WAKE_ALARM, 35, "cap-wake-alarm")                                    \
  _ (CAP_BLOCK_SUSPEND, 36, "cap-block-suspend")                              \
  _ (CAP_AUDIT_READ, 37, "cap-audit-read")

typedef enum
{
#define _(f, n, s) f = n,
  foreach_process_capabilities
#undef _
} vlib_process_capabilities_t;

#define CAP_LAST_CAP CAP_AUDIT_READ
#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)

#define CAP_TO_INDEX(x) ((x) >> 5)
#define CAP_TO_MASK(x)	(1 << ((x) &31))
#define CAP_BIT_SET(x)	(1ULL << x)

#endif
