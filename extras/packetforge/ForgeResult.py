# Copyright (c) 2022 Intel and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import ExpressionConverter


class ForgeResult:
    def __init__(self, Header, PacketBuffer, MaskBuffer):
        self.Headers = Header
        self.PacketBuffer = PacketBuffer
        self.MaskBuffer = MaskBuffer

    def ToJSON(self):
        result = {}
        result["Length"] = str(len(self.PacketBuffer))
        result["Packet"] = ExpressionConverter.ByteArrayToString(self.PacketBuffer)
        result["Mask"] = ExpressionConverter.ByteArrayToString(self.MaskBuffer)
        result["Protocol Stack"] = []

        for header in self.Headers:
            head_info = {}
            head_info["name"] = header.Name()
            head_info["Fields"] = []
            for field in header.fields:
                if field.Size == 0:
                    continue
                field_info = {}
                field_info["name"] = field.Field.Name
                field_info["size"] = str(field.Size)
                field_info["value"] = field.Value
                field_info["mask"] = field.Mask
                head_info["Fields"].append(field_info)
            result["Protocol Stack"].append(head_info)

        return result
