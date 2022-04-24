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


class ProtocolHeaderField:
    def __init__(self, Size, Value, Mask, Field):
        self.Size = Size
        self.Value = Value
        self.Mask = Mask
        self.Field = Field

    def UpdateValue(self, expression, auto):
        if self.Field.IsReadonly and not auto:
            return False

        if expression != None:
            ret, _ = ExpressionConverter.Verify(self.Field.Format, expression)
            if not ret:
                return False

        self.Value = expression
        return True

    def UpdateMask(self, expression):
        if expression != None:
            ret, _ = ExpressionConverter.Verify(self.Field.Format, expression)
            if not ret:
                return False

        self.Mask = expression
        return True

    def UpdateSize(self):
        if self.Size:
            return
        self.Size = self.Field.Size
