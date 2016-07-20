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

#
# jVpp binding
#

nobase_include_HEADERS =		\
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

jvpp/org_openvpp_jvpp_VppJNIConnection.h: $(prefix)/../vpp/vpp-api/vpe.api
	@echo "  jVpp API";				\
	cp -rf @srcdir@/jvpp/* -t jvpp/;			\
	mkdir -p jvpp/gen/target/org/openvpp/jvpp;				\
	cp -rf jvpp/org/openvpp/jvpp/* -t jvpp/gen/target/org/openvpp/jvpp/;	\
	$(CC) $(CPPFLAGS) -E -P -C -x c $<			                  \
	| vppapigen --input - --python defs_vpp_papi.py; 				\
	mkdir -p dto future callfacade callback notification; 	\
	./jvpp/gen/jvpp_gen.py -i defs_vpp_papi.py;				\
	cp -rf dto future callfacade callback notification *.java -t jvpp/gen/target/org/openvpp/jvpp/;	\
	cp -rf jvpp_gen.h -t jvpp/gen/target;	\
	rm -rf dto future callfacade callback notification *.java jvpp_gen.h;	\
	$(JAVAC) -classpath . -d . jvpp/gen/target/org/openvpp/jvpp/*.java \
		jvpp/gen/target/org/openvpp/jvpp/dto/*.java  \
		jvpp/gen/target/org/openvpp/jvpp/callback/*.java \
		jvpp/gen/target/org/openvpp/jvpp/notification/*.java \
		jvpp/gen/target/org/openvpp/jvpp/callfacade/*.java \
		jvpp/gen/target/org/openvpp/jvpp/future/*.java 	\
		jvpp/gen/target/org/openvpp/jvpp/test/*.java	\
		|| (echo "JVpp compilation failed: $$?"; exit 1);	\
	$(JAVAH) -classpath . -d jvpp org.openvpp.jvpp.VppJNIConnection ;	\
	$(JAVAH) -classpath . -d jvpp org.openvpp.jvpp.JVppImpl ;

$(jarfile_jvpp): libjvpp.la
	cd .libs ; $(JAR) cf $(JARFLAGS) ../$@ libjvpp.so.0.0.0 ../$(packagedir_jvpp)/* ; cd ..;

all-local: $(jarfile_jvpp)
