{#
# Copyright (c) 2016 Comcast Cable Communications Management, LLC.
#
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
#}
{% set v = item['value'] %}
{{ "@section %s %s" % (meta['label'], item['name']) }}
{% if 'siphon_block' in item['meta'] %}
{% set sb = item["meta"]["siphon_block"] %}
{% if sb %}
{# Extracted from the code in /*? ... ?*/ blocks #}

### Description

{{ sb }}
{% endif %}
{% endif %}
{% if "name" in meta or "function" in item %}
{# Gives some developer-useful linking #}

### Declaration and implementation
{% if "name" in meta %}

{{ "Declaration: @ref %s (@ref %s line %d)" %
   (meta['name'], meta["file"], item["meta"]["line_start"]) }}
{% endif %}
{% if "function" in item %}

{{ "Implementation: @ref %s." % item["function"] }}
{% endif %}
{% endif %}

