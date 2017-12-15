VAPI_BINDIR = $(BR)/vapi_test/
VAPI_CBIN = $(addprefix $(VAPI_BINDIR), vapi_c_test)
VAPI_CPPBIN = $(addprefix $(VAPI_BINDIR), vapi_cpp_test)
VOM_BINDIR = $(BR)/vom_test/
VOM_BIN = $(addprefix $(VOM_BINDIR), vom_test)

ifeq ($(filter rhel centos,$(OS_ID)),$(OS_ID))
VAPI_CPPBIN=
endif

VAPI_LIBS = -L$(VPP_TEST_BUILD_DIR)/vpp/.libs/ -L$(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/ -lvppinfra -lvlibmemoryclient -lsvm -lpthread -lcheck -lrt -lm -lvapiclient
ifneq ($(filter opensuse,$(OS_ID)),$(OS_ID))
VAPI_LIBS += -lsubunit
endif
CFLAGS = -std=gnu99 -g -Wall -pthread -I$(WS_ROOT)/src -I$(VPP_TEST_INSTALL_PATH)/vpp/include -I$(VAPI_BINDIR)
CPPFLAGS = -std=c++11 -g -Wall -pthread -I$(WS_ROOT)/src -I$(VPP_TEST_INSTALL_PATH)/vpp/include -I$(VAPI_BINDIR)

all: $(VAPI_CBIN) $(VAPI_CPPBIN) $(VOM_BINDIR) $(VOM_BIN)

$(VAPI_BINDIR):
	mkdir -p $(VAPI_BINDIR)

CSRC = vapi_c_test.c

$(VAPI_BINDIR)/fake.api.vapi.h: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_BINDIR)/fake.api.vapi.hpp: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_CBIN): $(CSRC) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvppinfra.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvlibmemoryclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libsvm.so $(VAPI_BINDIR)/fake.api.vapi.h
	$(CC) -o $@ $(CFLAGS) $(CSRC) $(VAPI_LIBS)

CPPSRC = vapi_cpp_test.cpp

$(VAPI_CPPBIN): $(CPPSRC) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvppinfra.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvlibmemoryclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libsvm.so $(VAPI_BINDIR)/fake.api.vapi.hpp
	$(CXX) -o $@ $(CPPFLAGS) $(CPPSRC) $(VAPI_LIBS)

VOM_CPPSRC = vom_test.cpp

$(VOM_BINDIR):
	mkdir -p $(VOM_BINDIR)

LIB_VOM = $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vom/.libs/libvom.so
VOM_LIBS = $(LIB_VOM) 	\
	-lboost_thread					\
	-lboost_system					\
	-lboost_filesystem				\
	-lboost_unit_test_framework			\
	$(VAPI_LIBS)

VOM_CPPFLAGS = \
	-I $(WS_ROOT)/src/vpp-api/ \
	$(CPPFLAGS)

$(VOM_BIN): $(VOM_CPPSRC) $(VOM_BINDIR) $(LIB_VOM) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so
	$(CXX) -o $@ $(VOM_CPPFLAGS) -DBOOST_LOG_DYN_LINK -O0 -g $(VOM_CPPSRC) $(VOM_LIBS)

clean:
	rm -rf $(VAPI_BINDIR) $(VOM_BINDIR)
