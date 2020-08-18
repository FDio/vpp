/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2005 Jouni Malinen <j@w1.fi>.
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

#ifndef __included_wg_convert_h__
#define __included_wg_convert_h__

#include <wg/wg.h>

bool base64_encode (const u8 * src, size_t src_len, u8 * out);
bool base64_decode (const u8 * src, size_t src_len, u8 * out);

#endif /* __included_wg_convert_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
