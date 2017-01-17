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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4
AM_LIBTOOLFLAGS = --quiet
AM_CFLAGS = -Wall -I${top_srcdir} -I${top_builddir}

BUILT_SOURCES =
bin_PROGRAMS =
CLEANFILES =
lib_LTLIBRARIES =
noinst_PROGRAMS =

#all-local:
#	(cd $(srcdir); $(PYTHON) setup.py build			\
#	--build-base $(shell readlink -f $(builddir))/build	\
#	--verbose)

#install-exec-local:
#	cd $(srcdir);							\
#	mkdir -p $(prefix)/lib/python2.7/site-packages; 		\
#	PYTHONUSERBASE=$(prefix)					\
#	python setup.py install --user

install-exec-local:
	(cd $(srcdir) ;	$(PYTHON) $(srcdir)/setup.py build			\
	--build-base $(shell readlink -f $(builddir))/build			\
	install									\
	--prefix $(DESTDIR)$(prefix)						\
	--single-version-externally-managed					\
	--record $(DESTDIR)$(pythondir)/vpp_papi/install_files.txt	\
	--verbose)
