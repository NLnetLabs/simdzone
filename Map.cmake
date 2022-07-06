#
# map.cmake -- generate lookup tables for zone parser.
#
# Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
#
# See LICENSE for the license.
#

if(NOT INPUT)
  message(FATAL_ERROR "INPUT not specified")
elseif(NOT EXISTS "${INPUT}")
  message(FATAL_ERROR "INPUT (${INPUT}) does not exist")
endif()

if(NOT TEMPLATE)
  message(FATAL_ERROR "TEMPLATE not specified")
elseif(NOT EXISTS "${TEMPLATE}")
  message(FATAL_ERROR "TEMPLATE (${TEMPLATE}) does not exist")
endif()

if(NOT OUTPUT)
  message(FATAL_ERROR "OUTPUT not specified")
endif()

file(TO_CMAKE_PATH "${INPUT}" input_file)
file(TO_CMAKE_PATH "${TEMPLATE}" template_file)
file(TO_CMAKE_PATH "${OUTPUT}" output_file)

file(STRINGS "${input_file}" input)

foreach(line ${input})
  if(line MATCHES "^([a-zA-Z0-9-]+):([0-9]+)([ \t]+([^\n]*))?")
    set(id "${CMAKE_MATCH_2}")
    string(TOLOWER "${CMAKE_MATCH_1}" name)
    list(APPEND map "${CMAKE_MATCH_1}:${CMAKE_MATCH_2}")
    list(APPEND names ${name})
    if(NOT maxid OR id GREATER maxid)
      set(maxid ${id})
    endif()
  endif()
endforeach()

list(SORT names) # sort alphabetically
list(REMOVE_DUPLICATES names)
# no need to sort numerically, traverse map on generating id to name array

set(separator "")
foreach(name ${names})
  foreach(entry ${map})
    string(TOLOWER "${entry}" entry_lower)
    if(NOT entry_lower MATCHES "^${name}:")
      continue()
    endif()
    string(REGEX REPLACE ":.*$" "" key "${entry}")
    string(REGEX REPLACE "^[^:]+:" "" id "${entry}")
    set(SORTED_LIST "${SORTED_LIST}${separator}MAP(\"${key}\", ${id})")
    set(separator ",\n")
    break()
  endforeach()
endforeach()

configure_file("${template_file}" "${output_file}" @ONLY)
