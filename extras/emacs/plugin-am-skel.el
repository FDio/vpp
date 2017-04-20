;;; plugin-am-skel.el - vpp engine plug-in foo.am skeleton
;;;
;;; Copyright (c) 2016 Cisco and/or its affiliates.
;;; Licensed under the Apache License, Version 2.0 (the "License");
;;; you may not use this file except in compliance with the License.
;;; You may obtain a copy of the License at:
;;;
;;;     http://www.apache.org/licenses/LICENSE-2.0
;;;
;;; Unless required by applicable law or agreed to in writing, software
;;; distributed under the License is distributed on an "AS IS" BASIS,
;;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;;; See the License for the specific language governing permissions and
;;; limitations under the License.

(require 'skeleton)

(define-skeleton skel-plugin-makefile-am-fragment
"Insert a plug-in 'foo.am' skeleton "
nil
'(if (not (boundp 'plugin-name))
     (setq plugin-name (read-string "Plugin name: ")))
'(setq PLUGIN-NAME (upcase plugin-name))
"
# Copyright (c) <current-year> <your-organization>
# Licensed under the Apache License, Version 2.0 (the \"License\");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an \"AS IS\" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

vppapitestplugins_LTLIBRARIES += " plugin-name "_test_plugin.la
vppplugins_LTLIBRARIES += " plugin-name "_plugin.la

" plugin-name "_plugin_la_SOURCES = \\
  " plugin-name "/node.c \\
  " plugin-name "/" plugin-name ".c \\
  " plugin-name "/" plugin-name ".h \\
  " plugin-name "/" plugin-name "_all_api_h.h \\
  " plugin-name "/" plugin-name "_msg_enum.h

API_FILES += " plugin-name "/" plugin-name ".api

nobase_apiinclude_HEADERS +=		\\
  " plugin-name "/" plugin-name "_all_api_h.h \\
  " plugin-name "/" plugin-name "_msg_enum.h \\
  " plugin-name "/" plugin-name ".api.h 

" plugin-name "_test_plugin_la_SOURCES = \\
  " plugin-name "/" plugin-name "_test.c \\
  " plugin-name "/" plugin-name ".api.h 

# vi:syntax=automake
")
