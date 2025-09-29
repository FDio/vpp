# x.cmake
file(READ "${FILE}" T)
string(REGEX REPLACE "#[^\n]*" "" T "${T}")                             # strip # to EOL
string(REGEX REPLACE "[ \t\r\n]+" " " T "${T}")    # collapse whitespace/newlines
string(REGEX MATCH "add_vpp_plugin *\\([^)]*\\)" M "${T}")
string(STRIP "${M}" M)
message("${M}")


function(add_vpp_plugin)
  cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})
  foreach(src IN LISTS ARG_SOURCES)
    message("SOURCE: ${src}")
  endforeach()
endfunction()

cmake_language(EVAL CODE "${M}")

