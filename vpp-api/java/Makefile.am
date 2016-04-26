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

nobase_include_HEADERS =		\
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
    ../../vpp/api/vpe.api.h
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
	vppapigen --input $${instdir}/../vpp/api/vpe.api --jni  japi/vppapi.c --app vpe ;	\
	vppapigen --input $${instdir}/../vpp/api/vpe.api --java japi/vppApi.java --app vpe ;	\
	$(JAVAC) -classpath . -d . japi/vppApi.java ;						\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppApi ;				\
	$(JAVAC) -classpath . -d . @srcdir@/japi/org/openvpp/vppjapi/vppApiCallbacks.java ;	\
	$(JAVAH) -classpath . -d japi org.openvpp.vppjapi.vppApiCallbacks ;

demo = japi/test/demo.class
$(demo): $(jarfile)
	$(JAVAC) -cp $(jarfile) -d $(JAVAROOT) @srcdir@/japi/test/demo.java

#
# jVpp binding
#

nobase_include_HEADERS +=		\
  jvpp/org_openvpp_jvpp_VppJNIConnection.h

lib_LTLIBRARIES += libjvpp.la

libjvpp_la_SOURCES = jvpp/jvpp.c
libjvpp_la_LIBADD = -lvlibmemoryclient -lvlibapi -lsvm -lvppinfra \
	              -lpthread -lm -lrt
libjvpp_la_LDFLAGS = -module
libjvpp_la_CPPFLAGS = -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

# todo make two jars api jar and impl jar
jarfile_jvpp = jvpp-$(PACKAGE_VERSION).jar
packagedir_jvpp = org/openvpp/jvpp
JAVAROOT = .

BUILT_SOURCES += jvpp/org_openvpp_jvpp_VppJNIConnection.h jvpp/jvpp.c

jvpp/org_openvpp_jvpp_VppJNIConnection.h: $(prefix)/../vpp/api/vpe.api
	@echo "  jVpp API";				\
	mkdir -p dto future callfacade callback @srcdir@/jvpp/gen/target/org/openvpp/jvpp;				\
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			                  \
	| vppapigen --input - --python defs_vpp_papi.py; 				\
	@srcdir@/jvpp/gen/jvpp_gen.py -i defs_vpp_papi.py;				\
	cp -rf dto future callfacade callback *.java -t @srcdir@/jvpp/gen/target/org/openvpp/jvpp/;				\
	cp -rf jvpp_gen.h -t @srcdir@/jvpp/gen/target;				\
	rm -rf dto future callfacade callback *.java jvpp_gen.h;				\
	$(JAVAC) -classpath . -d . @srcdir@/jvpp/org/openvpp/jvpp/*.java \
		@srcdir@/jvpp/org/openvpp/jvpp/dto/*.java  \
		@srcdir@/jvpp/org/openvpp/jvpp/callback/*.java \
		@srcdir@/jvpp/org/openvpp/jvpp/future/*.java  \
		@srcdir@/jvpp/org/openvpp/jvpp/test/*.java  \
		@srcdir@/jvpp/gen/target/org/openvpp/jvpp/*.java \
		@srcdir@/jvpp/gen/target/org/openvpp/jvpp/dto/*.java  \
		@srcdir@/jvpp/gen/target/org/openvpp/jvpp/callback/*.java \
		@srcdir@/jvpp/gen/target/org/openvpp/jvpp/callfacade/*.java \
		@srcdir@/jvpp/gen/target/org/openvpp/jvpp/future/*.java ; \
	$(JAVAH) -classpath . -d jvpp org.openvpp.jvpp.VppJNIConnection ;				\
	$(JAVAH) -classpath . -d jvpp org.openvpp.jvpp.JVppImpl ;

$(jarfile_jvpp): libjvpp.la
	cd .libs ; $(JAR) cf $(JARFLAGS) ../$@ libjvpp.so.0.0.0 ../$(packagedir_jvpp)/* ; cd ..

all-local: $(jarfile) $(jarfile_jvpp) $(demo)
