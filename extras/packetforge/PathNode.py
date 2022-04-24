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

from PathNodeField import *


class PathNode:
    def __init__(self):
        self.Header = None
        self.fields = []

    def Create(token):
        if token == None:
            return None

        config = PathNode()

        if "header" in token:
            config.Header = token["header"]
            if config.Header == None:
                return None

        if "fields" in token:
            fts = token["fields"]
            if fts != None:
                for ft in fts:
                    config.fields.append(PathNodeField.Create(ft))

        return config
