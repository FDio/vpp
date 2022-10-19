# Copyright (c) 2020 Cisco and/or its affiliates.
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

add_vpp_plugin(vhost
  SOURCES
  plugin.c
  vhost_user.c
  vhost_user_api.c
  vhost_user_input.c
  vhost_user_output.c
  vhost_std.h
  vhost_user.h
  vhost_user_inline.h
  virtio_std.h

  MULTIARCH_SOURCES
  vhost_user_input.c
  vhost_user_output.c

  API_FILES
  vhost_user.api
)
