/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* The API descriptors of memclnt.api, its messages are registered by hand. */

#include <vlibapi/api_desc.h>

extern const vl_api_desc_file_t memclnt_api_desc __attribute__ ((visibility ("hidden")));

const vl_api_desc_file_t *
vl_memclnt_api_desc (void)
{
  return &memclnt_api_desc;
}
