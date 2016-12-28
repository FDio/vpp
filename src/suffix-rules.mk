# Copyright (c) 2016 Cisco and/or its affiliates.
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

# Shared suffix rules
# Please do not set "SUFFIXES = .api.h .api" here

%.api.h: %.api @VPPAPIGEN@
	@echo "  APIGEN  " $@ ;					\
	mkdir -p `dirname $@` ;					\
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			\
	| @VPPAPIGEN@ --input - --output $@ --show-name $@ > /dev/null

%.api.json: %.api @VPPAPIGEN@
	@echo "  JSON API" $@ ;					\
	mkdir -p `dirname $@` ;					\
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			\
	| @VPPAPIGEN@ --input - --json $@ > /dev/null
