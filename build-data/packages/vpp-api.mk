vpp-api_configure_depend =			\
	vpp-install

vpp-api_CPPFLAGS = $(call installed_includes_fn,	\
	vpp)

vpp-api_LDFLAGS =

vpp-api_CPPFLAGS += -I/usr/lib/jvm/java-8-openjdk-amd64/include
