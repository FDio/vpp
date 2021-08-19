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
{% if 'short_help' in v %}
{% set str = v['short_help'] %}
{% set str = this.unescape(str) %}

{# Summary/usage #}
{{ item['value']['path'] }}
-------------------------------------------------------------------------

.. code-block:: console

    {{ this.reindent(str, 4) }}

{% endif %}
{% if 'long_help' in v %}
{% set long_help = v['long_help'] %}
{% set long_help = this.unescape(long_help) %}
{# This is seldom used and will likely be deprecated #}
{# Long help #}
.. code-block:: console

    {{ this.reindent(long_help, 4) }}

{% endif %}
{% if 'siphon_block' in item['meta'] %}
{% set sb = item["meta"]["siphon_block"] %}
{% set sb = this.process_special(sb) %}
{% if sb %}
{# Extracted from the code in /*? ... ?*/ blocks #}

{# Description #}

{{ sb }}
{% endif %}
{% endif %}
{% if 'name' in meta or 'function' in v %}
{# Gives some developer-useful linking #}

{% if "name" in meta %}
Declaration: ``{{ meta['name'] }}`` `{{ meta["file"] }} line {{ item["meta"]["line_start"] }} <{{ this.repository_link }}{{ meta["file"] }}#L{{ item["meta"]["line_start"] }}>`_
{% endif %}
{% if "function" in v %}

Implementation: ``{{ v["function"] }}``
{% endif %}
{% endif %}

