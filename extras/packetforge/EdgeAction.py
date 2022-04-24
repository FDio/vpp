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


class EdgeAction:
    def __init__(self):
        self.ToStartObject = None
        self.ToExpression = None
        self.FromStartObject = None
        self.FromExpression = None

    def Create(token):
        if token == None:
            return None

        dststr = token["dst"]
        srcstr = token["src"]

        if srcstr == None or dststr == None:
            return None

        action = EdgeAction()

        dststr = dststr.strip()
        srcstr = srcstr.strip()

        if dststr.startswith("start."):
            action.ToStartObject = True
            action.ToExpression = dststr[6:]
        elif dststr.startswith("end."):
            action.ToStartObject = False
            action.ToExpression = dststr[4:]
        else:
            return None

        if srcstr.startswith("start."):
            action.FromStartObject = True
            action.FromExpression = srcstr[6:]
        elif srcstr.startswith("end."):
            action.FromStartObject = False
            action.FromExpression = srcstr[4:]
        else:
            action.FromExpression = srcstr

        return action
