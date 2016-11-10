AUTOMAKE_OPTIONS = foreign
SUBDIRS = python java

api_json_dir = $(abs_builddir)/vpp-api
api_srcs:=$(shell find $(prefix)/../ -name '*.api')
api_json:=$(patsubst %.api,$(api_json_dir)/%.api.json,$(notdir $(api_srcs)))

define define_compile_rules
$(api_json_dir)/%.api.json: $(1)%.api
	@echo " + Generating '$$<'"
	@mkdir -p $$(@D)
	$(CC) $$(CPPFLAGS) -E -P -C -x c $$< | vppapigen --input - --json $$@
endef

$(foreach directory,$(dir $(api_srcs)),$(eval $(call define_compile_rules,$(directory))))

BUILT_SOURCES = $(api_json)
