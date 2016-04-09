# Copyright (c) 2015 Cisco and/or its affiliates.
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

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -Wall 

noinst_PROGRAMS = 
BUILT_SOURCES =
bin_PROGRAMS = 
CLEANFILES = 
lib_LTLIBRARIES = 
noinst_PROGRAMS = test_pneum
nobase_include_HEADERS = pneum/pneum.h

#
# Python binding
#
pneum_la_SOURCES = pneum/pneum_wrap.c pneum/pneum.c
pneum_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt
pneum_la_LDFLAGS = -module
pneum_la_CPPFLAGS = -I/usr/include/python3.4/
lib_LTLIBRARIES += pneum.la

BUILT_SOURCES += api_vpp_papi.py

api_vpp_papi.py: $(prefix)/../vpp/api/vpe.api papi/api-gen.py
	@echo "  PYTHON API";                                            	  \
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			                  \
	| vppapigen --input - --python defs_$@;                                   \
	echo "#include <api/vpe_msg_enum.h>"                                      \
	| $(CC) $(CPPFLAGS) -E -P -x c - | grep VL_API                            \
	| @srcdir@/papi/api-gen.py -i defs_$@ > $@

#
# Test client
#
noinst_PROGRAMS += test_pneum
test_pneum_SOURCES = pneum/pneum.c pneum/test_pneum.c
test_pneum_LDADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra -lpthread -lm -lrt

#
# Java binding
#

nobase_include_HEADERS +=		\
  japi/org_openvpp_vppjapi_vppApi.h	\
  japi/org_openvpp_vppjapi_vppConn.h

lib_LTLIBRARIES += libvppjni.la

libvppjni_la_SOURCES = japi/vppjni.c japi/vppapi.c japi/vppjni_env.h japi/vppjni_env.c
libvppjni_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libvppjni_la_LDFLAGS = -module
libvppjni_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

jarfile = vppjapi-$(PACKAGE_VERSION).jar
packagedir = org/openvpp/vppjapi
JAVAROOT = .

$(jarfile): libvppjni.la
	cd .libs ; $(JAR) cf $(JARFLAGS) ../$@ libvppjni.so.0.0.0 ../$(packagedir)/*.class ; cd ..

BUILT_SOURCES += japi/org_openvpp_vppjapi_vppConn.h japi/vppapi.c 

japi/org_openvpp_vppjapi_vppConn.h: 					\
    japi/org/openvpp/vppjapi/vppVersion.java 				\
    japi/org/openvpp/vppjapi/vppInterfaceDetails.java 			\
    japi/org/openvpp/vppjapi/vppInterfaceCounters.java 			\
    japi/org/openvpp/vppjapi/vppBridgeDomainDetails.java 		\
    japi/org/openvpp/vppjapi/vppBridgeDomainInterfaceDetails.java	\
    japi/org/openvpp/vppjapi/vppL2Fib.java 				\
    japi/org/openvpp/vppjapi/vppIPv4Address.java 			\
    japi/org/openvpp/vppjapi/vppIPv6Address.java 			\
    japi/org/openvpp/vppjapi/vppVxlanTunnelDetails.java 		\
    japi/org/openvpp/vppjapi/vppConn.java 				\
    japi/org/openvpp/vppjapi/vppApiCallbacks.java 			\
    ../vpp/api/vpe.api.h
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppVersion.java ;				\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppVersion ;						\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppInterfaceDetails.java ;			\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppInterfaceDetails ;					\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppInterfaceCounters.java ;		\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppInterfaceCounters ;				\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppBridgeDomainInterfaceDetails.java ;	\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppBridgeDomainInterfaceDetails ;			\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppBridgeDomainDetails.java ;		\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppBridgeDomainDetails ;				\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppL2Fib.java ;				\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppL2Fib ;						\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppIPv4Address.java ;			\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppIPv4Address ;					\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppIPv6Address.java ;			\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppIPv6Address ;					\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppVxlanTunnelDetails.java ;		\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppVxlanTunnelDetails ;				\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppConn.java ;				\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppConn ;

japi/vppapi.c: japi/org_openvpp_vppjapi_vppConn.h
	pushd .. ; dir=`pwd` ; popd ;								\
	instdir=`echo $${dir} | sed -e 's:build-root/build:build-root/install:'` ;		\
	vppapigen --input $${instdir}/vpp/api/vpe.api --jni  japi/vppapi.c --app vpe ;		\
	vppapigen --input $${instdir}/vpp/api/vpe.api --java japi/vppApi.java --app vpe ;	\
	$(JAVAC) -classpath . -d . japi/vppApi.java ;						\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppApi ;				\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppApiCallbacks.java ;	\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppApiCallbacks ;

demo = japi/test/demo.class
$(demo): $(jarfile)
	$(JAVAC) -cp $(jarfile) -d $(JAVAROOT) @srcdir@/japi/test/demo.java

all-local: $(jarfile) $(demo)
