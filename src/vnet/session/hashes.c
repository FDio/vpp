/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/** Generate typed init functions for multiple hash table styles... */

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

#undef __included_bihash_template_h__

#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>
