/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vom/route.hpp>

#include <vapi/ip.api.vapi.hpp>

namespace VOM {

vapi_enum_mfib_itf_flags to_api(const route::itf_flags_t& flags);
const route::itf_flags_t& from_api(vapi_enum_mfib_itf_flags flags);

void to_api(const route::path& p, vapi_type_fib_path& o);

route::path from_api(const vapi_type_fib_path& p);

vapi_enum_ip_dscp to_api(const ip_dscp_t& d);
const ip_dscp_t& from_api(vapi_enum_ip_dscp d);

}; // namespace VOM

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "mozilla")
 * End:
 */
