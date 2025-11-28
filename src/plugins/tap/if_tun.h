/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * Minimal TUN/TAP interface definitions derived from
 * include/uapi/linux/if_tun.h.
 */
#pragma once

#include <stdint.h>
#include <sys/ioctl.h>

/* ioctls */
#define TUNSETIFF	_IOW ('T', 202, int)
#define TUNSETPERSIST	_IOW ('T', 203, int)
#define TUNGETFEATURES	_IOR ('T', 207, unsigned int)
#define TUNSETOFFLOAD	_IOW ('T', 208, unsigned int)
#define TUNGETIFF	_IOR ('T', 210, int)
#define TUNSETSNDBUF	_IOW ('T', 212, int)
#define TUNSETVNETHDRSZ _IOW ('T', 216, int)
#define TUNSETCARRIER	_IOW ('T', 226, int)

#define foreach_tun_feature                                                   \
  _ (0, TUN)                                                                  \
  _ (1, TAP)                                                                  \
  _ (4, NAPI)                                                                 \
  _ (5, NAPI_FRAGS)                                                           \
  _ (6, NO_CARRIER)                                                           \
  _ (8, MULTI_QUEUE)                                                          \
  _ (9, ATTACH_QUEUE)                                                         \
  _ (10, DETACH_QUEUE)                                                        \
  _ (11, PERSIST)                                                             \
  _ (12, NO_PI)                                                               \
  _ (13, ONE_QUEUE)                                                           \
  _ (14, VNET_HDR)                                                            \
  _ (15, TUN_EXCL)

enum
{
#define _(bit, f) IFF_##f = (1u << (bit)),
  foreach_tun_feature
#undef _
};

#define foreach_tun_offload                                                   \
  _ (0, CSUM)                                                                 \
  _ (1, TSO4)                                                                 \
  _ (2, TSO6)                                                                 \
  _ (3, TSO_ECN)                                                              \
  _ (4, UFO)                                                                  \
  _ (5, USO4)                                                                 \
  _ (6, USO6)                                                                 \
  _ (7, UDP_TUNNEL_GSO)                                                       \
  _ (8, UDP_TUNNEL_GSO_CSUM)

enum
{
#define _(bit, f) TUN_F_##f = (1u << (bit)),
  foreach_tun_offload
#undef _
};
