# LICENSE

function(GENERATE_MAP _target _input _template _output)
  if(NOT _input)
    message(FATAL_ERROR "INPUT not specified")
  elseif(NOT _template)
    message(FATAL_ERROR "TEMPLATE not specified")
  elseif(NOT _output)
    message(FATAL_ERROR "OUTPUT not specified")
  endif()

  if(NOT IS_ABSOLUTE _input)
    set(_input "${CMAKE_CURRENT_SOURCE_DIR}/${_input}")
  endif()

  if(NOT IS_ABSOLUTE _template)
    set(_template "${CMAKE_CURRENT_SOURCE_DIR}/${_template}")
  endif()

  if(NOT IS_ABSOLUTE _output)
    set(_output "${CMAKE_CURRENT_BINARY_DIR}/${_output}")
  endif()

  add_custom_command(
    OUTPUT "${_output}"
    COMMAND ${CMAKE_COMMAND}
    ARGS
      "-DINPUT=${_input}"
      "-DTEMPLATE=${_template}"
      "-DOUTPUT=${_output}"
      "-P" "${CMAKE_SOURCE_DIR}/Map.cmake"
    DEPENDS
      "${_input}"
      "${_template}")
  add_custom_target(${_target}_generate DEPENDS ${_output})
  add_library(${_target} INTERFACE)
  get_filename_component(_output_dir "${_output}" DIRECTORY)
  target_include_directories(${_target} INTERFACE ${_output_dir})
  add_dependencies(${_target} ${_target}_generate)
endfunction()
