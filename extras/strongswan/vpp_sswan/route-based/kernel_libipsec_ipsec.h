/*
 * Copyright (c) 2023 Intel and/or its affiliates.
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

#ifndef KERNEL_LIBIPSEC_IPSEC_H_
#define KERNEL_LIBIPSEC_IPSEC_H_

#include <library.h>
#include <kernel/kernel_ipsec.h>

typedef struct kernel_libipsec_vpp_ipsec_t kernel_libipsec_vpp_ipsec_t;

/**
 * Implementation of the ipsec interface using libipsec
 */
struct kernel_libipsec_vpp_ipsec_t
{

  /**
   * Implements kernel_ipsec_t interface
   */
  kernel_ipsec_t interface;
};

/**
 * Create a libipsec ipsec interface instance.
 *
 * @return			kernel_libipsec_vpp_ipsec_t instance
 */
kernel_libipsec_vpp_ipsec_t *kernel_libipsec_vpp_ipsec_create ();

#endif /** KERNEL_LIBIPSEC_IPSEC_H_ */
