AUTOMAKE_OPTIONS = foreign
SUBDIRS = python java

api_json_dir = $(abs_builddir)/vpp-api/
api_srcs:=$(shell find $(prefix)/../ -name '*.api')
api_json:=$(addprefix $(api_json_dir),$(notdir $(api_srcs:.api=.api.json)))

SUFFIXES = .api .api.json

%.api.json: %.api
	@echo "  JSON APIGEN  " $@ ;		\
	mkdir -p `dirname $@` ;			\
	$(CC) $(CPPFLAGS) -E -P -C -x c $^	\
	| vppapigen --input - --json - > $@

jsonapicopy:
	mkdir -p $(api_json_dir) ; \
	$(foreach file,$(api_srcs),cp $(file) $(api_json_dir) ;)

install-exec-local: jsonapicopy $(api_json)
