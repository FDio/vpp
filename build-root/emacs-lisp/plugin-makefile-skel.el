;;; plugin-makefile-skel.el - vpp engine plug-in "main.c" skeleton
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

(define-skeleton skel-plugin-makefile
"Insert a plug-in 'Makefile.am' skeleton "
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

AUTOMAKE_OPTIONS = foreign subdir-objects

AM_CFLAGS = -Wall
AM_LDFLAGS = -module -shared -avoid-version

vppapitestpluginsdir = ${libdir}/vpp_api_test_plugins
vpppluginsdir = ${libdir}/vpp_plugins

vppplugins_LTLIBRARIES = " plugin-name "_plugin.la
vppapitestplugins_LTLIBRARIES = " plugin-name "_test_plugin.la

" plugin-name "_plugin_la_SOURCES = " plugin-name "/" plugin-name ".c  \\
        " plugin-name "/node.c \\
	" plugin-name "/" plugin-name "_plugin.api.h
" plugin-name "_plugin_la_LDFLAGS = -module

BUILT_SOURCES = " plugin-name "/" plugin-name ".api.h

SUFFIXES = .api.h .api

%.api.h: %.api
	mkdir -p `dirname $@` ; \\
	$(CC) $(CPPFLAGS) -E -P -C -x c $^ \\
	| vppapigen --input - --output $@ --show-name $@

noinst_HEADERS =			\\
  " plugin-name "/" plugin-name "_all_api_h.h			\\
  " plugin-name "/" plugin-name "_msg_enum.h			\\
  " plugin-name "/" plugin-name ".api.h

" plugin-name "_test_plugin_la_SOURCES = \\
  " plugin-name "/" plugin-name "_test.c " plugin-name "/" plugin-name "_plugin.api.h

# Remove *.la files
install-data-hook:
	@(cd $(vpppluginsdir) && $(RM) $(vppplugins_LTLIBRARIES))
	@(cd $(vppapitestpluginsdir) && $(RM) $(vppapitestplugins_LTLIBRARIES))
endif
")
