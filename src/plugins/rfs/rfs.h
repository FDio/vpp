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

#ifndef SRC_PLUGINS_RFS_RFS_H_
#define SRC_PLUGINS_RFS_RFS_H_

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>


#define foreach_rfs_error		\
  _ (NONE, "none")

typedef enum rfs_error_
{
#define _(n, s) RFS_ERROR_##n,
  foreach_rfs_error
#undef _
  RFS_N_ERROR,
} rfs_error_t;

#define foreach_rfs_handoff_error  	\
_(CONGESTION_DROP, "congestion drop")

typedef enum rfs_handoff_error_
{
#define _(n, s) RFS_HANDOFF_ERROR_##n,
  foreach_rfs_handoff_error
#undef _
  RFS_HANDOFF_N_ERROR,
} rfs_handoff_error_t;

#endif /* SRC_PLUGINS_RFS_RFS_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

