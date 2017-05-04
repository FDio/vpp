BINDIR = $(BR)/vapi_test/
BIN = $(addprefix $(BINDIR), vapi_test)
LIBS = -L$(VPP_TEST_BUILD_DIR)/vpp/.libs/ -L$(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/ -lvppinfra -lvlibmemoryclient -lsvm -lpthread -lcheck -lsubunit -lrt -lm -lvapiclient
CFLAGS = -ggdb -O0 -Wall -pthread -I$(WS_ROOT)/src -I$(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi -I$(WS_ROOT)/src/vpp-api/vapi/

all: $(BIN)

$(BINDIR):
	mkdir -p $(BINDIR)

SRC = vapi_test.c

$(BIN): $(SRC) $(BINDIR) $(VPP_TEST_BUILD_DIR)/vpp/vpp-api/vapi/.libs/libvapiclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvppinfra.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libvlibmemoryclient.so $(VPP_TEST_BUILD_DIR)/vpp/.libs/libsvm.so
	gcc -ggdb -o $@ $(SRC) $(CFLAGS) $(LIBS)

clean:
	rm -rf $(BINDIR)
