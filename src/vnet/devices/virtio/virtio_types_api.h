/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2025 Cisco and/or its affiliates.
 */

#pragma once

/**
 * Conversion functions to/from (decode/encode) API types to VPP internal types
 */

/**
 * These enum decode/encodes use 'u32' as the type for the enum because
 * one cannot forward declare an enum
 */
extern u64 virtio_features_decode (u32 first, u32 last);
extern void virtio_features_encode (u64 features, u32 *first, u32 *last);
