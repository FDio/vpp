/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
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
#include <vnet/feature/feature.h>

/** @file trace_classify.h
 * Use the vpp classifier to decide whether to trace packets
 */

static int
vnet_enable_disable_tracenode_feature (u32 sw_if_index, int is_pcap,
				       int enable)
{
  int rv;
  if (is_pcap)
    {
      if ((rv = vnet_feature_enable_disable ("ip4-unicast", "pcap-filtering",
					     sw_if_index, enable, 0, 0)) != 0)
	return rv;
      rv = vnet_feature_enable_disable ("ip6-unicast", "pcap-filtering",
					sw_if_index, enable, 0, 0);
    }
  else
    {
      if ((rv = vnet_feature_enable_disable ("ip4-unicast", "trace-filtering",
					     sw_if_index, enable, 0, 0)) != 0)
	return rv;
      rv = vnet_feature_enable_disable ("ip6-unicast", "trace-filtering",
					sw_if_index, enable, 0, 0);
    }
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
