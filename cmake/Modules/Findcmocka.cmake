#
# Findcmocka.cmake -- CMake module to locate cmocka library and generate a test runner from annotations
#
# Copyright (c) 2020-2023, Jeroen Koekkoek
#
# SPDX-License-Identifier: BSD-3-Clause
#
set(_cmocka_cmake_module_dir "${CMAKE_CURRENT_LIST_DIR}")

include(FindPackageHandleStandardArgs)

# cmocka provides cmocka-config.cmake.
# Conan managed dependencies best use the cmake_find_package_multi generator.
find_package(cmocka CONFIG)

if(NOT cmocka_FOUND)
  find_package(PkgConfig)

  pkg_search_module(_pc_cmocka QUIET cmocka)
  set(_include_hints ${CONAN_INCLUDE_DIRS_CMOCKA} ${_pc_cmocka_INCLUDEDIR})
  set(_library_hints ${CONAN_LIB_DIRS_CMOCKA} ${_pc_cmocka_LIBDIR})

  find_path(CMOCKA_INCLUDE_DIR cmocka.h HINTS ${_include_hints})
  find_library(CMOCKA_LIBRARY cmocka HINTS ${_library_hints})
  if(_pc_cmocka_FOUND AND
     _pc_cmocka_INCLUDEDIR STREQUAL "${CMOCKA_INCLUDE_DIR}" AND
     _pc_cmocka_LIBDIR STREQUAL "${CMOCKA_LIBRARY_DIR}")
    set(cmocka_VERSION ${_pc_cmocka_VERSION})
  endif()
else()
  set(_cmake "[Cc][Mm][Aa][Kk][Ee]")
  set(_cmocka "[Cc][Mm][Oo][Cc][Kk][Aa]")

  if(CMOCKA_CMAKE_DIR MATCHES "[\\/]${_cmake}([\\/]+${_cmocka})?$")
    string(REGEX REPLACE "[\\/]+${_cmake}([\\/]+${_cmocka})?$" "" _dir "${CMOCKA_CMAKE_DIR}")
    # cmocka-config.cmake on Windows initializes CMOCKA_INCLUDE_DIR and
    # CMOCKA_LIBRARY with relative paths.
    if(NOT IS_ABSOLUTE "${CMOCKA_INCLUDE_DIR}" AND
           EXISTS "${_dir}/${CMOCKA_INCLUDE_DIR}")
      get_filename_component(
        CMOCKA_INCLUDE_DIR "${_dir}/${CMOCKA_INCLUDE_DIR}" ABSOLUTE)
    endif()
    if(NOT IS_ABSOLUTE "${CMOCKA_LIBRARY}" AND
           EXISTS "${_dir}/${CMOCKA_LIBRARY}")
      get_filename_component(
        CMOCKA_LIBRARY "${_dir}/${CMOCKA_LIBRARY}" ABSOLUTE)
    endif()
  endif()
endif()

if(cmocka_FOUND)
  if(NOT TARGET cmocka::cmocka)
    if(WIN32)
      get_filename_component(_cmocka_library_dir "${CMOCKA_LIBRARY}}" PATH)
      get_filename_component(_cmocka_prefix "${_cmocka_library_dir}" PATH)
      get_filename_component(_cmocka_name "${CMOCKA_LIBRARY}}" NAME_WE)

      find_program(
        _cmocka_dll
          "${CMAKE_SHARED_LIBRARY_PREFIX}${_cmocka_name}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        HINTS
          ${_cmocka_prefix}
        PATH_SUFFIXES
          bin
        NO_DEFAULT_PATH)
      if(_cmocka_dll)
        add_library(cmocka::cmocka SHARED IMPORTED)
        set_target_properties(
          cmocka::cmocka PROPERTIES IMPORTED_IMPLIB "${CMOCKA_LIBRARY}")
        set_target_properties(
          cmocka::cmocka PROPERTIES IMPORTED_LOCATION "${_cmocka_dll}")
      else()
        add_library(cmocka::cmocka STATIC IMPORTED)
        set_target_properties(
          cmocka::cmocka PROPERTIES IMPORTED_LOCATION "${CMOCKA_LIBRARY}")
      endif()
    else()
      add_library(cmocka::cmocka UNKNOWN IMPORTED)
      set_target_properties(
        cmocka::cmocka PROPERTIES IMPORTED_LOCATION "${CMOCKA_LIBRARY}")
    endif()

    set_target_properties(
      cmocka::cmocka PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${CMOCKA_INCLUDE_DIR}")
  else()
    # Newer versions of cmocka-config.cmake do NOT set CMOCKA_INCLUDE_DIR and
    # CMOCKA_LIBRARY anymore. Set them here for backwards compatibility.
    # FIXME: This may use outdated methodologies(?)
    if(NOT CMOCKA_INCLUDE_DIR)
      get_target_property(
        CMOCKA_INCLUDE_DIR cmocka::cmocka INTERFACE_INCLUDE_DIRECTORIES)
    endif()
    if(NOT CMOCKA_LIBRARY)
      # Prefer specified target
      get_target_property(
        _configurations cmocka::cmocka IMPORTED_CONFIGURATIONS)
      get_target_property(
        _location cmocka::cmocka IMPORTED_LOCATION)
      foreach(_configuration ${_configurations})
        if(NOT _location)
          get_target_property(
            _location cmocka::cmocka IMPORTED_LOCATION_${_configuration})
        elseif(_configuration STREQUAL CMAKE_BUILD_TYPE)
          get_target_property(
            _location cmocka::cmocka IMPORTED_LOCATION_${_configuration})
          break()
        endif()
      endforeach()
      set(CMOCKA_LIBRARY ${_location})
    endif()
  endif()
endif()


find_package_handle_standard_args(
  cmocka
  FOUND_VAR cmocka_FOUND
  REQUIRED_VARS CMOCKA_LIBRARY CMOCKA_INCLUDE_DIR
  VERSION_VAR cmocka_VERSION)


set(__h "[ \t]") # horizontal whitespace
set(__n "(\r\n|\n\r|\r|\n)") # newline
set(__s "[ \t\r\n]") # whitespace
set(__S "[^ \t\r\n]") # non-whitespace
set(__w "[_a-zA-Z0-9]")
set(__identifier "[_a-zA-Z]${__w}*")
set(__declarator "\\[${__s}*[0-9]*${__s}*\\]")
set(__type "(${__identifier}\\**${__s}+[ \t\r\n\\*]*)+")
set(__parameter "${__s}*${__type}${__identifier}(${__s}*${__declarator})*${__s}*")
set(__parameter_list "${__parameter}(,${__parameter})*")
set(__marker "\\[<<\\[([0-9]+)\\]>>\\]")
set(__function_signature "${__type}${__identifier}${__s}*\\(${__parameter_list}\\)")
set(__specifier "(group|setup|teardown|test)")

function(__cmocka_parse_group_fixtures _var _line)
  set(__setup "setup${__h}*:${__h}*(${__identifier})")
  set(__teardown "teardown${__h}*:${__h}*(${__identifier})")

  # setup:<function>
  if(_line MATCHES "(^|${__h})${__setup}(${__h}|$)")
    list(APPEND _fixtures "setup:${CMAKE_MATCH_2}")
  else()
    list(APPEND _fixtures "setup:NULL")
  endif()
  # teardown=<function>
  if(_line MATCHES "(^|${__h})${__teardown}(${__h}|$)")
    list(APPEND _fixtures "teardown:${CMAKE_MATCH_2}")
  else()
    list(APPEND _fixtures "teardown:NULL")
  endif()

  set(${_var} ${_fixtures} PARENT_SCOPE)
endfunction()

function(__cmocka_parse_test_fixtures _var _line)
  set(__true "([tT][rR][uU][eE])")
  set(__false "([fF][aA][lL][sS][eE])")
  set(__disabled "disabled${__h}*:${__h}*(${__true}|${__false})")
  set(__timeout "timeout${__h}*:${__h}*([0-9]+)")
  set(__group "group${__h}*:${__h}*(${__identifier})")

  __cmocka_parse_group_fixtures(_fixtures "${_line}")
  # disabled=<true|false>
  if(_line MATCHES "(^|${__h})${__disabled}(${__h}|$)")
    if(CMAKE_MATCH_2 MATCHES "${__true}")
      list(APPEND _fixtures "disabled:TRUE")
    else()
      list(APPEND _fixtures "disabled:FALSE")
    endif()
  else()
    list(APPEND _fixtures "disabled:FALSE")
  endif()
  # timeout=<seconds>
  if(_line MATCHES "(^|${__h})${__timeout}(${__h}|$)")
    list(APPEND _fixtures "timeout:${CMAKE_MATCH_2}")
  else()
    list(APPEND _fixtures "timeout:0")
  endif()
  # group=<identifier>
  if(_line MATCHES "(^|${__h})${__group}(${__h}|$)")
    list(APPEND _fixtures "group:${CMAKE_MATCH_2}")
  else()
    list(APPEND _fixtures "group:")
  endif()

  set(${_var} ${_fixtures} PARENT_SCOPE)
endfunction()

function(__cmocka_parse_directive _var _line)
  # Non-capture groups are not supported in CMake regular expressions and the
  # hard-limit on number of groups makes better pragma recognition impossible.
  string(REGEX REPLACE "^${__s}*/\\*!cmocka${__s}*" "" _line "${_line}")
  string(REGEX REPLACE "\\*/${__s}*$" "" _line "${_line}")
  string(REGEX REPLACE "${__n}" " " _line "${_line}")

  # Strip fixtures for correct specifier and identifier matching.
  string(REGEX REPLACE "(${__S}+${__s}*:${__s}*${__S}+)" "" _head "${_line}")

  set(_specifier)
  set(_name)

  # Strip (and store) optional specifier
  if(_head MATCHES "^${__specifier}(${__s}*|$)")
    set(_specifier "${CMAKE_MATCH_1}")
    string(LENGTH "${CMAKE_MATCH_1}${CMAKE_MATCH_2}" _length)
    string(SUBSTRING "${_head}" ${_length} -1 _head)
    string(SUBSTRING "${_line}" ${_length} -1 _line)
  endif()
  # Strip (and store) optional identifier
  if(_head MATCHES "^(${__identifier})(${__s}|$)")
    set(_name "${CMAKE_MATCH_1}")
    string(LENGTH "${CMAKE_MATCH_1}${CMAKE_MATCH_2}" _length)
    string(SUBSTRING "${_head}" ${_length} -1 _head)
    string(SUBSTRING "${_line}" ${_length} -1 _line)
  endif()

  # Strip leading and trailing whitespace
  string(STRIP "${_line}" _line)

  if(_specifier MATCHES "^(group)$")
    if(_name)
      __cmocka_parse_group_fixtures(_fixtures "${_line}")
      string(REPLACE ";" ":" _fixtures "${_fixtures}")
      set(${_var} "group:${_name}:${_fixtures}" PARENT_SCOPE)
    else()
      set(${_var} "error:group directive without name" PARENT_SCOPE)
    endif()
  elseif(_specifier MATCHES "^(setup|teardown)$")
    if(_line)
      set(${_var} "error:${_specifier} directive with fixtures" PARENT_SCOPE)
    else()
      set(${_var} "setup:${_name}" PARENT_SCOPE)
    endif()
  elseif(_name AND NOT _specifier)
    set(${_var} "error:directive with name but no specifier" PARENT_SCOPE)
  else()
    __cmocka_parse_test_fixtures(_fixtures "${_line}")
    string(REPLACE ";" ":" _fixtures "${_fixtures}")
    set(${_var} "${_specifier}:${_name}:${_fixtures}" PARENT_SCOPE)
  endif()
endfunction()

function(__cmocka_parse_function_signature _var _line)
  # Strip parameter-list
  if(_line MATCHES "\\((${__parameter_list})\\)")
    set(_parameter_list "${CMAKE_MATCH_1}")
    string(REGEX REPLACE "\\(${__parameter_list}\\)" "" _line "${_line}")
  endif()
  # Strip and store function name
  if(_line MATCHES "(${__identifier})${__s}*$")
    set(_name "${CMAKE_MATCH_1}")
    string(REGEX REPLACE "${__identifier}${__s}*$" "" _line "${_line}")
  endif()

  string(STRIP "${_line}" _type)
  string(STRIP "${_name}" _name)
  string(STRIP "${_parameter_list}" _parameter_list)

  # Discard function if parameter-list does not consist of a single void**
  if(_parameter_list MATCHES "^void${__s}*\\*${__s}*\\*${__s}*${__identifier}$")
    if(_type STREQUAL "void")
      set(${_var} "test:${_name}" PARENT_SCOPE)
    elseif(_type STREQUAL "int")
      set(${_var} "setup:${_name}" PARENT_SCOPE)
    else()
      set(${_var} ":" PARENT_SCOPE)
    endif()
  else()
    set(${_var} ":" PARENT_SCOPE)
  endif()
endfunction()

macro(__cmocka_strip _out_var _in_var _length)
  if(${_length} GREATER_EQUAL 0)
    string(SUBSTRING "${${_in_var}}" 0 ${_length} __substring)
    string(APPEND ${_out_var} "${__substring}")
    string(SUBSTRING "${${_in_var}}" ${_length} -1 ${_in_var})
  else()
    string(APPEND ${_out_var} "${${_in_var}}")
    set(${_in_var} "")
  endif()
endmacro()

macro(__cmocka_strip_literal _out_var _in_var _char)
  __cmocka_strip(${_out_var} ${_in_var} 1)

  string(FIND "${${_in_var}}" "\n" __newline)
  while(TRUE)
    string(FIND "${${_in_var}}" "\\" __escape)
    string(FIND "${${_in_var}}" "${_char}" __quote)

    if(__quote EQUAL -1 OR __quote GREATER __newline)
      message(FATAL_ERROR "unterminated literal in ${_file}")
    endif()

    if(__escape GREATER_EQUAL 0 AND __escape LESS __quote)
      math(EXPR __escape "${__escape} + 2")
      __cmocka_strip(${_out_var} ${_in_var} ${__escape})
    else()
      math(EXPR __quote "${__quote} + 1")
      __cmocka_strip(${_out_var} ${_in_var} ${__quote})
      break()
    endif()
  endwhile()
endmacro()

macro(__cmocka_strip_string_literal _out_var _in_var)
  __cmocka_strip_literal(${_out_var} ${_in_var} "\"")
endmacro()

macro(__cmocka_strip_character_literal _out_var _in_var)
  __cmocka_strip_literal(${_out_var} ${_in_var} "\'")
endmacro()

macro(__cmocka_strip_cxx_comment _out_var _in_var)
  __cmocka_strip(${_out_var} ${_in_var} 2) # strip //
  string(FIND "${${_in_var}}" "\n" __length)
  __cmocka_strip(${_out_var} ${_in_var} ${__length})
endmacro()

macro(__cmocka_strip_comment _out_var _in_var)
  __cmocka_strip(${_out_var} ${_in_var} 2) # strip /*
  string(FIND "${${_in_var}}" "*/" __length)
  if(__length EQUAL -1)
    message(FATAL_ERROR "unterminated comment in ${_file}")
  endif()
  math(EXPR __length "${__length} + 2")
  __cmocka_strip(${_out_var} ${_in_var} ${__length})
endmacro()

function(__cmocka_parse_file _var _file)
  # Default group is basename converted to an identifier
  get_filename_component(_basename "${_file}" NAME_WE)
  string(MAKE_C_IDENTIFIER "${_basename}" _default_group)

  file(READ "${_file}" _code)

  # Strip line continuation sequences
  string(REGEX REPLACE "\\\\${__n}" "" _code "${_code}")

  # This is where the "fun" starts. Python, or any other dynamic language for
  # that matter, would have resulted in much cleaner code. CMake is used
  # solely in the interest of dependency minimisation. Needless to say, string
  # operations in CMake can definitely be improved.

  set(_serial 0)
  set(_view)

  # First pass strips comments and extracts /*!cmocka*/ annotations and swaps
  # them out for a unique marker. Blocks are stored in ad hoc created
  # variables named _block_<serial> because comments may contain semicolons,
  # which are used to interpret variables as lists in CMake too.
  while(TRUE)
    string(FIND "${_code}" "/*" _cmnt)
    string(FIND "${_code}" "//" _cxx_cmnt)
    string(FIND "${_code}" "\"" _dquot)
    string(FIND "${_code}" "\'" _squot)

    set(_block "")

    # Strip string literal
    if(_dquot GREATER -1 AND (_dquot LESS _squot    OR _squot    EQUAL -1)
                         AND (_dquot LESS _cxx_cmnt OR _cxx_cmnt EQUAL -1)
                         AND (_dquot LESS _cmnt     OR _cmnt     EQUAL -1))
      __cmocka_strip(_view _code ${_dquot})
      __cmocka_strip_string_literal(_block _code)
      string(APPEND _view "\"!\"") # syntax correctness
    # Strip character literal
    elseif(_squot GREATER -1 AND (_squot LESS _cxx_cmnt OR _cxx_cmt EQUAL -1)
                             AND (_squot LESS _cmnt     OR _cmnt    EQUAL -1))
      __cmocka_strip(_view _code ${_squot})
      __cmocka_strip_character_literal(_block _code)
      string(APPEND _view "\'!\'") # syntax correctness
    # Strip C++ comment
    elseif(_cxx_cmnt GREATER -1 AND (_cxx_cmnt LESS _cmnt OR _cmnt EQUAL -1))
      __cmocka_strip(_view _code ${_cxx_cmnt})
      __cmocka_strip_cxx_comment(_block _code)
    # Strip comment
    elseif(_cmnt GREATER -1)
      __cmocka_strip(_view _code ${_cmnt})
      __cmocka_strip_comment(_block _code)
      if(_block MATCHES "^/\\*!cmocka")
        # Put marker to search for in second pass
        string(APPEND _view "[<<[${_serial}]>>]")
        set(_block_${_serial} "${_block}")
        math(EXPR _serial "${_serial} + 1")
      else()
        # Put space to avoid incidental creation/invalidation of token
        string(APPEND _view " ")
      endif()
    else()
      __cmocka_strip(_view _code -1)
      break()
    endif()
  endwhile()

  # Second pass extracts unique markers and the function signature
  # (if applicable), to allow for shorthand notation.
  string(REGEX MATCHALL "${__marker}${__s}*(${__function_signature})?" _matches "${_view}")
  foreach(_m ${_matches})
    # Split marker from function signature
    string(REGEX REPLACE "^${__marker}${__s}.*" "\\1" _serial "${_m}")
    string(REGEX REPLACE "^${__marker}${__s}"    "" _function "${_m}")

    __cmocka_parse_directive(_directive "${_block_${_serial}}")
    __cmocka_parse_function_signature(_function "${_function}")

    # Error may have been detected when the directive was parsed. Message is
    # printed here to include the source file.
    string(REPLACE ":" ";" _directive "${_directive}")
    string(REPLACE ":" ";" _function "${_function}")

    list(GET _directive 0 _specifier)
    list(GET _directive 1 _error)
    if(_specifier STREQUAL "discard")
      continue()
    endif()
    if(_specifier STREQUAL "error")
      message(FATAL_ERROR "${_error} in ${_file}")
    endif()

    # Determine name and type for pragma since both can be implicit if pragma
    # is used to annotate a function. The name and type must match that of the
    # function signature if the pragma defines them explicitly.
    list(GET _directive 0 _spec)
    list(GET _function  0 _function_spec)
    list(GET _directive 1 _name)
    list(GET _function  1 _function_name)

    if(NOT _name AND NOT _function_name)
      message(FATAL_ERROR "directive without name in ${_file}")
    elseif(NOT _name)
      set(_name "${_function_name}")
    elseif(_name AND _function_name AND NOT _name STREQUAL _function_name)
      # not an annotation for function.
      unset(_function_spec)
      unset(_function_name)
    endif()

    if(NOT _spec AND NOT _function_spec)
      message(FATAL_ERROR "directive without type in ${_file}")
    elseif(NOT _spec)
      set(_spec "${_function_spec}")
    elseif(_spec AND _function_spec AND NOT _spec STREQUAL _function_spec)
      # type specifier and function type specifier do not match.
      message(FATAL_ERROR "type mismatch for directive ${_name} in ${_file}")
    endif()

    if(_spec STREQUAL "group")
      set(_default_group "${_name}")
    elseif(_spec STREQUAL "test")
      list(GET _directive 11 _group)
      if(NOT _group)
        list(REMOVE_AT _directive 11)
        list(INSERT _directive 11 "${_default_group}")
      endif()
    endif()

    list(REMOVE_AT _directive 0 1)
    list(INSERT _directive 0 "${_spec}")
    list(INSERT _directive 1 "${_name}")
    string(REPLACE ";" ":" _directive "${_directive}")
    list(APPEND _directives "${_directive}")
  endforeach()

  set(${_var} "${_directives}" PARENT_SCOPE)
endfunction()

macro(_cmocka_assert_fixture _list _fixture)
  if(NOT ${_fixture} STREQUAL "NULL" AND
     NOT ${_fixture} IN_LIST ${_list})
    message(FATAL_ERROR "use of undefined fixture ${_fixture}")
  endif()
endmacro()

macro(_cmocka_append_fixture _list _fixture)
  if(NOT ${_fixture} STREQUAL "NULL")
    list(APPEND ${_list} ${_fixture})
  endif()
endmacro()

# The AddCMockaTest.cmake module that ships with cmocka, exports a function
# named add_cmocka_test that creates a single executable for multiple tests.
function(cmocka_add_tests _target)
  # Get location of shared library to:
  #  1) Extend the PATH environment variable on Microsoft Windows so that the
  #     linker can locate the .dll that it was linked against.
  #  2) Set the DYLD_LIBRARY_PATH environment variable on macOS so that the
  #     linker can locate the .dylib that it was linked against.
  get_target_property(
    _cmocka_library_type cmocka::cmocka TYPE)
  get_target_property(
    _cmocka_imported_location cmocka::cmocka IMPORTED_LOCATION)
  get_filename_component(
    _cmocka_library_dir "${_cmocka_imported_location}" PATH)

  # FIXME: Make CTest prefix configurable.

  set(_groups)
  set(_groups_seen)
  set(_tests_seen)
  set(_fixtures_seen)

  foreach(_file ${ARGN})
    # Resolve to absolute path
    get_filename_component(_file "${_file}" ABSOLUTE)
    list(APPEND _files "${_file}")
    unset(_directives)
    __cmocka_parse_file(_directives "${_file}")
    # Sort by group to ease code generation and so groups can span files
    foreach(_directive ${_directives})
      string(REPLACE ":" ";" _d "${_directive}")
      list(GET _d 0 _type)
      list(GET _d 1 _name)
      if(_type STREQUAL "group")
        list(APPEND _groups "${_directive}")
      elseif(_type STREQUAL "test")
        if(_name IN_LIST _tests_seen)
          message(FATAL_ERROR "test ${_name} redefined in ${_file}")
        endif()
        list(GET _d 11 _group)
        list(APPEND _tests_seen "${_name}")
        list(APPEND _groups_seen "${_group}")
        list(APPEND _${_group}_tests "${_directive}")
      else()
        if(_name IN_LIST _fixtures_seen)
          message(FATAL_ERROR "${_type} ${_name} redefined in ${_file}")
        endif()
        list(APPEND _fixtures_seen "${_name}")
      endif()
    endforeach()
  endforeach()

  list(REMOVE_DUPLICATES _groups_seen)

  set(_groups_code)
  set(_fixtures_code)

  foreach(_group ${_groups_seen})
    # Group is not required to have a directive (no setup or teardown)
    set(_setup "NULL")
    set(_teardown "NULL")
    foreach(_directive ${_groups})
      if(_directive MATCHES "^group:${_group}:")
        string(REPLACE ":" ";" _d "${_directive}")
        list(GET _d 3 _setup)
        list(GET _d 5 _teardown)
        break()
      endif()
    endforeach()

    _cmocka_assert_fixture(_fixtures_seen ${_setup})
    _cmocka_assert_fixture(_fixtures_seen ${_teardown})
    _cmocka_append_fixture(_fixtures ${_setup})
    _cmocka_append_fixture(_fixtures ${_teardown})
    list(APPEND _groups_code
      "exec_tests(${_group}, ${_setup}, ${_teardown})")

    foreach(_directive ${_${_group}_tests})
      string(REPLACE ":" ";" _d "${_directive}")
      list(GET _d 1 _test)
      list(GET _d 3 _setup)
      list(GET _d 5 _teardown)
      list(GET _d 7 _disabled)
      list(GET _d 9 _timeout)

      _cmocka_assert_fixture(_fixtures_seen ${_setup})
      _cmocka_assert_fixture(_fixtures_seen ${_teardown})
      _cmocka_append_fixture(_fixtures ${_setup})
      _cmocka_append_fixture(_fixtures ${_teardown})
      list(APPEND _tests "${_test}")
      list(APPEND _${_group}_tests_code "${_test}, ${_setup}, ${_teardown}")

      set(_name "${_prefix}${_test}")
      add_test(
        NAME "${_name}"
        COMMAND ${_target} -g "${_group}" -t "${_test}")
      set_property(TEST ${_name} PROPERTY TIMEOUT ${_timeout})
      set_property(TEST ${_name} PROPERTY DISABLED ${_disabled})
      if(APPLE)
        set_property(
          TEST ${_name}
          PROPERTY ENVIRONMENT
            "DYLD_LIBRARY_PATH=${_cmocka_library_dir}:$ENV{DYLD_LIBRARY_PATH}")
      elseif(WIN32 AND _cmocka_library_type STREQUAL "SHARED_LIBRARY")
        set_property(
          TEST ${_name}
          PROPERTY ENVIRONMENT
            "PATH=${_cmocka_library_dir};$ENV{PATH}")
      endif()
    endforeach()
    unset(${_group}_tests)
  endforeach()

  # Generate test runner code
  set(_glue "")
  foreach(_i ${_fixtures})
    string(APPEND cmocka_functions "${_glue}extern int ${_i}(void **state);")
    set(_glue "\n")
  endforeach()

  foreach(_i ${_tests})
    string(APPEND cmocka_functions "${_glue}extern void ${_i}(void **state);")
    set(_glue "\n")
  endforeach()

  set(_glue "")
  foreach(_group ${_groups_seen})
    string(APPEND cmocka_test_groups
      "${_glue}static const struct CMUnitTest ${_group} [] = {\n")
    set(_sep "")
    foreach(_i ${_${_group}_tests_code})
      string(APPEND cmocka_test_groups
        "${_sep}  cmocka_unit_test_setup_teardown(${_i})")
      set(_sep ",\n")
    endforeach()
    string(APPEND cmocka_test_groups "\n};")
    set(_glue "\n\n")
    unset(_${_group}_tests_code)
  endforeach()

  set(_glue "")
  foreach(_i ${_groups_code})
    string(APPEND cmocka_run_tests "${_glue}${_i};")
    set(_glue "\n")
  endforeach()

  configure_file(
    "${_cmocka_cmake_module_dir}/Findcmocka/runner.c.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${_target}.c" @ONLY)
  add_executable(
    ${_target} "${CMAKE_CURRENT_BINARY_DIR}/${_target}.c" ${_files})
  target_link_libraries(${_target} PRIVATE cmocka::cmocka)
endfunction()
