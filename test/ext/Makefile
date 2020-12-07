TEST_EXT_DIR=$(TEST_DIR)/ext
VAPI_BINDIR = $(TEST_BR)/vapi_test
VAPI_CBIN = $(addprefix $(VAPI_BINDIR), /vapi_c_test)
VAPI_CPPBIN = $(addprefix $(VAPI_BINDIR), /vapi_cpp_test)

VAPI_LIBS = \
  -L$(VPP_INSTALL_PATH)/vpp/lib \
  -lvppinfra -lvlibmemoryclient -lsvm -lpthread -lcheck -lrt -lm -lvapiclient

ifneq ($(filter centos,$(OS_ID)),$(OS_ID))
VAPI_LIBS += -lsubunit
endif

FLAGS = -g -Wall -lstdc++ -pthread -I$(WS_ROOT)/src -I$(VPP_INSTALL_PATH)/vpp/include -I$(VAPI_BINDIR)
CFLAGS = -std=gnu99 $(FLAGS)
CPPFLAGS = -std=c++11 $(FLAGS)

$(VAPI_BINDIR):
	@mkdir -p $(VAPI_BINDIR)

CSRC = $(TEST_EXT_DIR)/vapi_c_test.c

$(VAPI_BINDIR)/fake.api.vapi.h: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_c_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_BINDIR)/fake.api.vapi.hpp: fake.api.json $(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py | $(VAPI_BINDIR)
	$(WS_ROOT)/src/vpp-api/vapi/vapi_cpp_gen.py --prefix $(VAPI_BINDIR) $<

$(VAPI_CBIN): $(CSRC) $(VAPI_BINDIR)/fake.api.vapi.h | $(VAPI_BINDIR)
	$(CC) -o $@ $(CFLAGS) $(CSRC) $(VAPI_LIBS)

$(VAPI_CBIN).d: $(CSRC) $(VAPI_BINDIR)/fake.api.vapi.h
	$(CC) -o $@ $(CFLAGS) -MM -MT '$(VAPI_CBIN)' $(CSRC) > $@


ifeq ($(filter rhel centos,$(OS_ID)),$(OS_ID))
ifeq ($(OS_VERSION_ID),7)
VAPI_CPPBIN=
endif
else
CPPSRC = $(TEST_EXT_DIR)/vapi_cpp_test.cpp

$(VAPI_CPPBIN): $(CPPSRC) $(VAPI_BINDIR)/fake.api.vapi.hpp | $(VAPI_BINDIR)
	$(CXX) -o $@ $(CPPFLAGS) $(CPPSRC) $(VAPI_LIBS)

$(VAPI_CPPBIN).d: $(CPPSRC) $(VAPI_BINDIR)/fake.api.vapi.hpp
	$(CXX) -o $@ $(CPPFLAGS) -MM -MT '$(VAPI_CPPBIN)' $(CPPSRC) > $@
endif

.PHONY: test-apps
test-apps: $(VAPI_CBIN) $(VAPI_CPPBIN)

.PHONY: clean
clean:
	@rm -rf $(VAPI_BINDIR)

ifneq ($(MAKECMDGOALS),clean)
-include $(VAPI_CBIN).d
ifneq ($(VAPI_CPPBIN),)
-include $(VAPI_CPPBIN).d
endif
endif
