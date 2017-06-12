BINDIR = $(BR)/vapi_test/
CBIN = $(addprefix $(BINDIR), vapi_c_test)
CPPBIN = $(addprefix $(BINDIR), vapi_cpp_test)

LIBS = -L$(VPP_TEST_BUILD_DIR)/vpp/.libs/ -L$(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/ -lvppinfra -lvlibmemoryclient -lsvm -lpthread -lcheck -lsubunit -lrt -lm -lvapiclient
CFLAGS = -std=gnu99 -g -Wall -pthread -I$(WS_ROOT)/src -I$(VPP_TEST_INSTALL_PATH)/vpp/include -I$(BINDIR)
CPPFLAGS = -std=c++11 -g -Wall -pthread -I$(WS_ROOT)/src -I$(VPP_TEST_INSTALL_PATH)/vpp/include -I$(BINDIR)

all: $(CBIN) $(CPPBIN)

$(BINDIR):
	mkdir -p $(BINDIR)

CSRC = vapi_c_test.c

fake.api.vapi.h: fake.api.json $(BINDIR) $(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py
	$(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py --prefix $(BINDIR) $<

fake.api.vapi.hpp: fake.api.json $(BINDIR) $(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py
	$(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py --prefix $(BINDIR) $<

$(CBIN): $(CSRC) $(BINDIR) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvppinfra.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvlibmemoryclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libsvm.so fake.api.vapi.h
	$(CC) -o $@ $(CFLAGS) $(CSRC) $(LIBS)

CPPSRC = vapi_cpp_test.cpp

$(CPPBIN): $(CPPSRC) $(BINDIR) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvppinfra.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvlibmemoryclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libsvm.so fake.api.vapi.hpp
	$(CXX) -o $@ $(CPPFLAGS) $(CPPSRC) $(LIBS)

clean:
	rm -rf $(BINDIR)
