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


class PathNodeField:
    def __init__(self):
        self.Name = None
        self.Value = None
        self.Mask = None

    def Create(token):
        if token == None:
            return None

        field = PathNodeField()

        if "name" in token:
            field.Name = token["name"]
        if "value" in token:
            field.Value = token["value"]
        if "mask" in token:
            field.Mask = token["mask"]

        if field.Name == None:
            return None

        return field
