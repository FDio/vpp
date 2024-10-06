/*
 * Copyright (c) 2024 InMon Corp.
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

SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_IIFINDEX, 4, "input if_index")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_OIFINDEX, 4, "output if_index")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_ORIGSIZE, 4, "original packet size")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_SAMPLE_GROUP, 4, "group number")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_GROUP_SEQ, 4, "group sequence number")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_SAMPLE_RATE, 4, "sampling N")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_DATA, 0, "sampled header")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_TUNNEL, 0, "tunnel header")

/* commands attributes */
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_GROUP_REFCOUNT, 0,
		   "group reference count")

SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_PAD, 0, "pad bytes")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_OUT_TC, 2, "egress queue number")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_OUT_TC_OCC, 8,
		   "egress queue depth in bytes")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_LATENCY, 8,
		   "transit latency in nanoseconds")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_TIMESTAMP, 8, "timestamp")
SFLOWPS_FIELDDATA (SFLOWPS_PSAMPLE_ATTR_PROTO, 2, "header protocol")
