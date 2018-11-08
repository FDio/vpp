VAPI_BINDIR = $(TEST_DIR)/build/vapi_test/
VAPI_CBIN = $(addprefix $(VAPI_BINDIR), vapi_c_test)
VAPI_CPPBIN = $(addprefix $(VAPI_BINDIR), vapi_cpp_test)
VOM_BINDIR = $(TEST_DIR)/build/vom_test/
VOM_BIN = $(addprefix $(VOM_BINDIR), vom_test)

ifeq ($(filter rhel centos,$(OS_ID)),$(OS_ID))
VAPI_CPPBIN=
endif

VAPI_LIBS = \
  -L$(VPP_INSTALL_PATH)/vpp/lib \
  -lvppinfra -lvlibmemoryclient -lsvm -lpthread -lcheck -lrt -lm -lvapiclient

ifneq ($(filter centos opensuse opensuse-tumbleweed opensuse-leap,$(OS_ID)),$(OS_ID))
VAPI_LIBS += -lsubunit
endif

FLAGS = -g -Wall -lstdc++ -pthread -I$(WS_ROOT)/src -I$(VPP_INSTALL_PATH)/vpp/include -I$(VAPI_BINDIR)
CFLAGS = -std=gnu99 $(FLAGS)
CPPFLAGS = -std=c++11 $(FLAGS) -I$(WS_ROOT)/extras/vom

all: $(VAPI_CBIN) $(VAPI_CPPBIN) $(VOM_BIN)

$(VAPI_BINDIR):
	mkdir -p $(VAPI_BINDIR)

CSRC = vapi_c_test.c

$(VAPI_BINDIR)/fake.api.vapi.h: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_BINDIR)/fake.api.vapi.hpp: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_CBIN): $(CSRC) $(VAPI_BINDIR)/fake.api.vapi.h
	$(CC) -o $@ $(CFLAGS) $(CSRC) $(VAPI_LIBS)

$(VAPI_CBIN).d: $(CSRC) $(VAPI_BINDIR)/fake.api.vapi.h
	$(CC) -o $@ $(CFLAGS) -MM -MT '$(VAPI_CBIN)' $(CSRC) > $@


CPPSRC = vapi_cpp_test.cpp

$(VAPI_CPPBIN): $(CPPSRC) $(VAPI_BINDIR)/fake.api.vapi.hpp
	$(CXX) -o $@ $(CPPFLAGS) $(CPPSRC) $(VAPI_LIBS)

$(VAPI_CPPBIN).d: $(CPPSRC) $(VAPI_BINDIR)/fake.api.vapi.hpp
	$(CXX) -o $@ $(CPPFLAGS) -MM -MT '$(VAPI_CPPBIN)' $(CPPSRC) > $@

VOM_CPPSRC = vom_test.cpp

$(VOM_BINDIR):
	mkdir -p $(VOM_BINDIR)

LIB_VOM = -lvom
VOM_LIBS = \
	-L$(VPP_INSTALL_PATH)/vom/lib \
	-lvom						\
	-lboost_thread					\
	-lboost_system					\
	-lboost_filesystem				\
	-lboost_unit_test_framework			\
	$(VAPI_LIBS)

VOM_CPPFLAGS = \
	-I $(WS_ROOT)/src/vpp-api/ \
	-DBOOST_LOG_DYN_LINK \
	$(CPPFLAGS)

$(VOM_BIN): $(VOM_CPPSRC) $(VOM_BINDIR)
	$(CXX) -o $@ $(VOM_CPPFLAGS) -O0 -g $(VOM_CPPSRC) $(VOM_LIBS) -Wl,-rpath,$(VPP_INSTALL_PATH)/vom/lib

$(VOM_BIN).d: $(VOM_CPPSRC) $(VOM_BINDIR)
	$(CXX) -o $@ $(VOM_CPPFLAGS) -MM -MT '$(VOM_BIN)' $(VOM_CPPSRC) > $@


clean:
	rm -rf $(VAPI_BINDIR) $(VOM_BINDIR)

ifneq ($(MAKECMDGOALS),clean)
-include $(VAPI_CPPBIN).d
-include $(VAPI_CBIN).d
-include $(VOM_BIN).d
endif

