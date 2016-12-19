AUTOMAKE_OPTIONS = foreign subdir-objects

PRE_DATA_SIZE = 

include vppinfra.am
include vppapigen.am

if !WITH_TOOLS_ONLY
include vlib.am
include svm.am
include vlib-api.am
include vnet.am
include vpp.am
endif
