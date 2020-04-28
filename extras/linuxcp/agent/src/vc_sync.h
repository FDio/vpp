/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __VC_SYNC_H__
#define __VC_SYNC_H__

#include <vapi/vapi.h>

#define VC_DECLARE_SYNC_TOKEN static bool __vc_sync_token

#define VC_SYNC_WAIT(_ctx)                              \
{                                                       \
    while (__vc_sync_token == true)                     \
    {                                                   \
        vapi_dispatch(_ctx);                            \
    }                                                   \
}

#define VC_SYNC_COMPLETE() __vc_sync_token = true
#define VC_SYNC_START() __vc_sync_token = false

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
