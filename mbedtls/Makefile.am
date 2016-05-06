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

AM_CFLAGS = -Wall

lib_LTLIBRARIES = libmbedtls.la 

libmbedtls_la_SOURCES =						\
	include/mbedtls/bignum.h include/mbedtls/bn_mul.h	\
	include/mbedtls/rsa.h include/mbedtls/sha256.h		\
	include/mbedtls/config.h include/mbedtls/check_config.h \
	include/mbedtls/md.h					\
	library/bignum.c library/rsa.c library/sha256.c		\
	library/md.c library/md_wrap.c library/sha512.c		\
	library/md5.c library/ripemd160.c library/asn1parse.c	\
	library/oid.c

nobase_include_HEADERS =					\
	include/mbedtls/bignum.h include/mbedtls/bn_mul.h	\
	include/mbedtls/rsa.h include/mbedtls/sha256.h		\
	include/mbedtls/config.h include/mbedtls/check_config.h	\
	include/mbedtls/md.h
