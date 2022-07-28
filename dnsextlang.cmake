#
# dnsextlang.cmake -- generate record descriptors from dnsextlang stanzas
#
# Copyright (c) 2022, NLnet Labs. All rights reserved.
#
# See LICENSE for the license.
#
#

cmake_minimum_required(VERSION 3.10)

# generator adapted from draft-levine-dnsextlang-12
# https://datatracker.ietf.org/doc/html/draft-levine-dnsextlang-12
#
# additions:
#   * Add Z[SVCB] to denote SvcParam fields to support SVCB and HTTPS records
#   * Add L as a qualifier for type T to denote TTL fields

# ALPHA, DIGIT and WSP as specified by RFC5234
#
# ALPHA  %x41-5A / %x61-7A   ; A-Z / a-z
# DIGIT  %x30-39             ; 0-9
# HTAB   %x09                ; horizontal tab
# SP     %x20                ; space
# WSP    SP / HTAB           ; white space
set(ALPHA "[a-zA-Z]")
set(DIGIT "[0-9]")
set(WSP "[ \t]")

set(ldh "${__ALPHA}[a-zA-Z0-9-]*")
# field types as defined in section 3.1 (R mentioned in section 3.5.1)
set(ftype "(I1|I2|I4|A|AA|AAAA|N|S|B32|B64|X|EUI48|EUI64|T|Z|R)")

# Some fields require overrides. e.g. the protocol field in the WKS record
# must retain context information and fields representing a time-to-live are
# generally expected to accept values like "1h2m3s"
set(overrides "11:1:typed:parse_wks_protocol"
              "11:1:generic:parse_generic_wks_protocol")

set(I1_type_print "ZONE_INT8")
set(I2_type_print "ZONE_INT16")
set(I4_type_print "ZONE_INT32")
set(A_type_print "ZONE_IP4")
set(AAAA_type_print "ZONE_IP6")
set(N_type_print "ZONE_NAME")
set(S_type_print "ZONE_STRING")
set(B32_type_print "ZONE_BASE32")
set(B64_type_print "ZONE_BASE64")
set(T_type_print "ZONE_INT32")
set(X_type_print "ZONE_BINARY")
set(Z_SVCB_type_print "ZONE_SVC_PARAM")
set(Z_WKS_type_print "ZONE_WKS")
set(Z_NXT_type_print "ZONE_NXT")

# Options (record types)
#   X: Implementing the RRTYPE requires extra processing
set(X_opt_print "ZONE_COMPLEX")
#   I: Type defined in IN class only
set(I_opt_print "ZONE_IN")
#   A: Type defined in ANY class
set(A_opt_print "ZONE_ANY")
#   O: Type is obsolete
set(O_opt_print "ZONE_OBSOLETE")
#   E: Type is experimental
set(E_opt_print "ZONE_EXPERIMENTAL")

# Qualifiers (rdata fields)
#
# Integer fields
#   ldh=1*DIGIT: Defines one or more symbolic field values
set(I1_qual "(${ldh}=${DIGIT}+)")
set(I2_qual "(${ldh}=${DIGIT}+)")
set(I4_qual "(${ldb}=${DIGIT}+)")
set(R_qual "[L]") # R[L] only mentioned in section 3.5.1
# IP address and partial address fields
set(A_qual)
set(AA_qual)
set(AAAA_qual)
# Domain name fields, section 3.5.3
#   C: Domain name is compressed
set(N_C_qual_print "ZONE_COMPRESSED")
#   A: Domain name represents a mailbox
set(N_A_qual_print "ZONE_MAILBOX")
#   L: Domain name is converted to lower case before DNSSEC validation
set(N_L_qual_print "ZONE_LOWER_CASE")
#   O: Domain name is optional and can only appear as the last field
set(N_L_qual_print "ZONE_OPTIONAL")
set(N_qual "[CALO]")
# Type fields
set(R_L_qual_print "ZONE_TYPE")
set(R_qual "[L]")
# String fields
#   S: Single string preceded by a one-octet length.
#   S[M]: Multiple strings, each stored as a length and string. Must be last!
set(S_M_qual_print "ZONE_SEQUENCE")
#   S[X]: Raw string, without any length bytes. Must be last!
set(S_X_qual_print "ZONE_UNBOUNDED")
set(S_qual "[MX]")
# Base-32 and Base-64 fields
set(B32_qual)
set(B64_qual)
# Hex fields
#   X: Binary data. Must be last. May include spaces for readability.
#   X[C]: Stored as a string with a preceding one-octet length.
set(X_qual "[C]")
# Time stamp fields
#   T: Time. Require "YYYYMMDDHHmmSS" notation.
#   T[L]: Time-to-live. Allow for "1h2m3s" notation and disallow use of MSB.
set(T_L_qual_print "ZONE_TTL")
set(T_qual "[L]")
# Miscellaneous fields
#   Z[WKS]: Bitmap of port numbers in the WKS RRTYPE.
#   Z[NSAP]: Special hex syntax for the address in the NSAP RRTYPE.
#   Z[NXT]: Bitmap of RRTYPES in the NXT RRTYPE.
#   Z[A6P] + Z[A6S]: Prefix length and the variable length address suffix in the A6 RRTYPE.
#   Z[APL]: List of address prefixes in the APL RRTYPE.
#   Z[IPSECKEY]: Variable format gateway in the IPSECKEY RRTYPE.
#   Z[HIPHIT] + Z[HIPKK]: Hex HIT and base64 PK fields with detached implicit lengths in the HIP RRTYPE.
#   Z[SVCB]: Service parameters in the SVCB and HTTPS RRTYPEs.
set(Z_qual "(WKS|NSAP|NXT|A6P|A6S|APL|IPSECKEY|HIPHIT|SVCB)")

if(NOT STANZAS)
  message(FATAL_ERROR "STANZAS file to read not specified")
elseif(NOT EXISTS ${STANZAS})
  message(FATAL_ERROR "STANZAS file (${STANZAS}) does not exist")
endif()

if(NOT TEMPLATE)
  message(FATAL_ERROR "TEMPLATE file to read not specified")
elseif(NOT EXISTS ${TEMPLATE})
  message(FATAL_ERROR "TEMPLATE file (${TEMPLATE}) does not exist")
endif()

if(NOT HEADER)
  message(FATAL_ERROR "HEADER file to generate not specified")
endif()

# Maximum number of types descriptors directly accessible by type code to
# avoid generating a humongous descriptor array. e.g. DLV record type is
# assigned type code 32769 by IANA.
if(NOT INDEXED)
  set(INDEXED 258)
endif()

set(lineno 0)
set(maxid 0)

file(READ ${STANZAS} input)
while(1)
  string(FIND "${input}" "\n" lf) # UNIX
  string(FIND "${input}" "\r\n" crlf) # Windows
  string(FIND "${input}" "\r" cr) # Macintosh

  if (lf GREATER -1 AND (lf LESS crlf OR crlf EQUAL -1)
                    AND (lf LESS cr   OR cr   EQUAL -1))
    set(newline ${lf})
  elseif(crlf GREATER -1 AND (crlf LESS cr OR cr EQUAL -1))
    set(newline ${crlf})
  elseif(cr GREATER -1)
    set(newline ${cr})
  else()
    set(newline -1)
  endif()

  string(SUBSTRING "${input}" 0 ${newline} line)
  math(EXPR lineno "${lineno} + 1")

  # ignore blank lines and lines where the first nonblank character is "#"
  if(line MATCHES "^${WSP}*(#.*)?$")
    # discard
  elseif(line MATCHES "^(${ldh}):(${DIGIT}+)((:[a-zA-Z])*)(${WSP}+.*)?$")
    set(name "${CMAKE_MATCH_1}")
    string(TOLOWER "${name}" lname) # normalize name
    string(TOUPPER "${CMAKE_MATCH_3}" opts)
    # cleanup id
    string(REGEX REPLACE "^0+" "" id "${CMAKE_MATCH_2}")
    # cleanup options
    string(REGEX REPLACE "^:" "" opts "${opts}")
    string(REGEX REPLACE ":" ";" opts "${opts}")
    # cleanup description
    string(REGEX REPLACE "^[^ \t]+" "" desc "${line}")
    string(STRIP "${desc}" desc)

    # ensure name and identifier are not in use
    foreach(type ${types})
      string(TOLOWER "${type}" ltype)
      if(ltype MATCHES "${lname}:.*")
        message(FATAL_ERROR "Type ${type} was previously defined")
      elseif(type MATCHES "^[^:]+:${id}$")
        message(FATAL_ERROR "Type identifier ${id} was previously assigned")
      endif()
    endforeach()

    # Set highest id to generate name to id mapping
    if(NOT maxid OR id GREATER maxid)
      set(maxid ${id})
    endif()
    list(APPEND names "${name}")
    list(APPEND codes "${id}")
    list(APPEND types "${name}:${id}")
    set(fid 0)
    set(_${id}_opts "${opts}")
    set(_${id}_desc "${desc}")
  elseif(name AND line MATCHES "^${WSP}+${ftype}(\\[[a-zA-Z0-9=,-]+\\])?(:${ldh})?(${WSP}+.*)?$")
    string(TOUPPER "${CMAKE_MATCH_1}" field)
    string(TOUPPER "${CMAKE_MATCH_2}" quals)
    string(STRIP "${CMAKE_MATCH_3}" tag)
    string(STRIP "${CMAKE_MATCH_4}" desc)
    # cleanup qualifiers
    string(REGEX REPLACE "(^\\[[ \t]*|[ \t]*\\]$)" "" quals "${quals}")
    string(REGEX REPLACE "[ \t]*,+[ \t]*" ";" quals "${quals}")
    # sort qualifiers alphabetically
    list(SORT quals CASE INSENSITIVE)
    # cleanup tag
    string(REGEX REPLACE "^:" "" tag "${tag}")

    list(APPEND _${id}_fields "${field}:${tag}")
    set(_${id}_${fid}_desc "${desc}")
    set(_${id}_${fid}_quals "${quals}")
    if(field MATCHES "^I[0-9]$")
      foreach(qual ${quals})
        if(NOT qual MATCHES "${ldh}=[0-9]")
          message(FATAL_ERROR "Invalid symbolic value ${qual} for ${field} on line ${lineno}")
        endif()
      endforeach()
    else()
      foreach(qual ${quals})
        if(NOT qual MATCHES "^${${field}_qual}$")
          message(FATAL_ERROR "Unsupported qualifier ${qual} for ${field} on line ${lineno}")
        endif()
      endforeach()
    endif()
    math(EXPR fid "${fid} + 1")
  else()
    # syntax error, throw error, bail, etc
    message(FATAL_ERROR "Invalid record or field definition on line ${lineno}")
  endif()

  if (newline EQUAL -1)
    break()
  endif()
  math(EXPR newline "${newline} + 1")
  string(SUBSTRING "${input}" ${newline} -1 input)
endwhile()

list(SORT names) # sort alphabetically

# generate name map
set(sep "")
foreach(name ${names})
  foreach(type ${types})
    if(NOT type MATCHES "^${name}:")
      continue()
    endif()
    string(REGEX REPLACE "^[^:]+:" "" id "${type}")
    set(NAMES "${NAMES}${sep}{ \"${name}\", sizeof(\"${name}\") - 1, ${id} }")
    set(sep ",\n")
    break()
  endforeach()
endforeach()

# generate descriptor map, indexed by type id
set(gap 0)
set(sparse 0)

set(sep "")
foreach(id RANGE ${maxid})
  if(NOT id IN_LIST codes)
    # Descriptors for the most common record types must be directly accessible
    # using the corresponding type code for performance reasons. To limit the
    # amount of memory required, no dummy entries are generated for types
    # beyond the user configurable maximum if the array becomes spares.
    if(id GREATER ${INDEXED} AND (sparse OR gap GREATER 10))
      set(sparse 1)
      continue()
    endif()
  endif()

  set(descr)
  foreach(type ${types})
    if(NOT type MATCHES "^[^:]+:${id}$")
      continue()
    endif()

    string(REGEX REPLACE ":.*$" "" name "${type}")

    # options
    set(opts)
    if(_${id}_opts)
      set(optsep "")
      foreach(opt ${_${id}_opts})
        if(DEFINED ${opt}_opt_print)
          set(opts "${opts}${optsep}${${opt}_opt_print}")
          set(optsep" | ")
        endif()
      endforeach()
    else()
      set(opts "0")
    endif()

    # description
    set(desc "")
    if(_${id}_desc)
      set(desc "${_${id}_desc}")
      # FIXME: can be implemented in more robust fashion...
      string(REPLACE "\"" "\\\"" desc "${desc}")
    endif()

    set(fid "0")
    set(fsep "")
    unset(rdata)
    unset(rdatas)
    foreach(field ${_${id}_fields})
      string(REGEX REPLACE ":.*$" "" ftype "${field}")
      string(REGEX REPLACE "^[^:]+:" "" fname "${field}")

      set(fquals "0")
      set(flabels "{ .map = NULL, .count = 0 }")
      if(ftype MATCHES "I[0-9]+") # labels
        if(_${id}_${fid}_quals)
          set(flabels "{ .map = (zone_map_t[]){ ")
          set(flabelid "")
          set(flabellen 0)
          set(flabelsep "")
          foreach(fqual ${_${id}_${fid}_quals})
            string(REGEX REPLACE "=.*$" "" flabel "${fqual}")
            string(REGEX REPLACE "^[^=]+=" "" flabelid "${fqual}")
            STRING(CONCAT flabels
              "${flabels}" "${flabelsep}"
              "{ \"${flabel}\", sizeof(\"${flabel}\") - 1, ${flabelid} }")
            set(flabelsep ", ")
            math(EXPR flabellen "${flabellen} + 1")
          endforeach()
          set(flabels "${flabels}${flabelsep} }, .count = ${flabellen} }")
        endif()
      elseif(_${id}_${fid}_quals) # qualifiers
        set(fquals "")
        set(fqualsep "")
        foreach(fqual ${_${id}_${fid}_quals})
          if(NOT ${ftype}_${fqual}_qual_print)
            continue()
          endif()
          set(fquals "${fquals}${fqualsep}${${ftype}_${fqual}_qual_print}")
          set(fqualsep " | ")
        endforeach()
      endif()

      if(_${id}_${fid}_desc)
        set(fdesc "${_${id}_${fid}_desc}")
        # FIXME: implement in more robust fashion
        string(REPLACE "\"" "\\\"" fdesc "${fdesc}")
        set(fdesc "\"${fdesc}\"")
      else()
        set(fdesc "NULL")
      endif()

      set(typed "0")
      set(generic "0")
      set(accept "0")
      if(ftype STREQUAL "T")
        set(typename "ZONE_INT32")
        if(_${id}_${fid}_quals STREQUAL "L")
          set(fquals "ZONE_TTL")
          set(typed "parse_ttl")
        else()
          set(fquals "ZONE_TIME")
          set(typed "parse_time")
        endif()
      elseif(ftype STREQUAL "R")
        if(_${id}_${fid}_quals STREQUAL "L")
          set(typename "ZONE_NSEC")
          set(fquals "0")
        else()
          set(typename "ZONE_INT16")
          set(fquals "ZONE_TYPE")
          set(typed "parse_type")
        endif()
      elseif(ftype STREQUAL "X")
        set(typename "ZONE_BINARY")
        if(_${id}_${fid}_quals STREQUAL "C")
          set(fquals "0")
        else()
          set(fquals "ZONE_UNBOUNDED")
        endif()
      elseif(ftype STREQUAL "Z")
        set(typename "${${ftype}_${_${id}_${fid}_quals}_type_print}")
        set(fquals "0")
      else()
        set(typename "${${ftype}_type_print}")
      endif()

      foreach(func "typed" "generic" "accept")
        foreach(override ${overrides})
          if(override MATCHES "^${id}:${fid}:${func}:([^ \t]+)")
            set(${func} "${CMAKE_MATCH_1}")
            break()
          endif()
        endforeach()
      endforeach()

      string(CONCAT rdata
        "${rdata}" "${fsep}" "{ "
        ".public = { "
          ".name = \"${fname}\", "
          ".length = sizeof(\"${fname}\") - 1, "
          ".type = ${typename}, "
          ".qualifiers = ${fquals}, "
          ".labels = ${flabels}, "
          ".description = ${fdesc} "
        "}, "
        ".typed = ${typed}, "
        ".generic = ${generic}, "
        ".accept = ${accept} "
        "}")

      math(EXPR fid "${fid} + 1")
      set(fsep ",\n")
    endforeach()

    if(rdata)
      set(rdatas "(struct rdata_descriptor[]){ ${rdata}, { { NULL, 0, 0, 0, { NULL, 0 }, NULL } } }")
    else()
      set(rdatas "(struct rdata_descriptor[]){ { { NULL, 0, 0, 0, { NULL, 0 }, NULL } } }")
    endif()

    string(CONCAT descr
      "{ "
      ".public = { "
        ".name = \"${name}\", "
        ".length = sizeof(\"${name}\") - 1, "
        ".type = ${id}, "
        ".options = ${opts}, "
        ".description = \"${desc}\" "
      "}, "
      ".rdata = ${rdatas} }")
    break()
  endforeach()

  if(NOT descr)
    math(EXPR gap "${gap} + 1")
    set(descr "{ .public = { .name = NULL, .length = 0, .options = 0, .description = NULL }, .rdata = NULL }")
  endif()

  set(DESCRIPTORS "${DESCRIPTORS}${sep}${descr}")
  set(sep ",\n")
endforeach()

configure_file("${TEMPLATE}" "${HEADER}" @ONLY)
