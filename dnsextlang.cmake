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

# Some fields require overrides. e.g. the protocol field in the WKS record
# must retain context information and fields representing a time-to-live are
# generally expected to accept values like "1h2m3s"
set(overrides "11:1:typed:parse_wks_protocol")

# dnsextlang defines a simple language to define DNS records. Field types and
# qualifiers specified are very much inspired by the textual representation.
# e.g. X, B32 and B64 types are derived from the way rdata fields are
# represented in zone files. The aforementioned rdata fields all appear on
# the wire as binary data with the length, in all cases, being the rdlength
# minus the length of all preceding rdata. The zone parser aims to abstract
# the presentation format, therefore types are derived from how rdata appears
# on the wire.
#
# The zone parser defines, among others, STRING and BLOB types (inspired by
# relational database terminology). STRING types consist of a length octet
# followed by a maximum of 255 octets containing the data. BLOB types
# consist solely of the data with their length being the rdlength minus the
# length of all preceding rdata. As a result, BLOB types are required to be
# last.
#
# Examples:
#   X, B32, B64 and S[X] are presented as BLOBs with BASE16, BASE32, BASE64
#   and <no-qualifier> qualifiers to describe their textual representation.
#
#   X[C] and S are presented as STRINGs with BASE16 and <no-qualifier> to
#   define their textual representation. STRINGs with a BASE16 qualifiers
#   actually require two fields for textual representation. One for the
#   length of the rdata and one for the rdata itself.
#
# As the wire type depends on the textual type plus qualifiers, no
# straightforward mapping is possible. <type>_<qual>_type_print mappings are
# preferred. If no such mapping exists, <type>_type_print is used.
# <type>_<qual>_type_print require qualifiers to be specified in
# <type>_<qual>_qual_print. <type>_qual_print specifies qualifiers for
# <type>_type_print. Qualifiers in <type>_<qual>_qual_print with a qualifier
# different from the qualifier used to map the type are always communicated.

# Qualifiers (rdata fields)
#
# Integer fields
#   ldh=1*DIGIT: Defines one or more symbolic field values
set(I1_qual "(${ldh}=${DIGIT}+)")
set(I2_qual "(${ldh}=${DIGIT}+)")
set(I4_qual "(${ldb}=${DIGIT}+)")
set(I1_type_print "ZONE_INT8:parse_int8:0:0")
set(I2_type_print "ZONE_INT16:parse_int16:0:0")
set(I4_type_print "ZONE_INT32:parse_int32:0:0")
# IP address and partial address fields
set(A_qual)
set(A_type_print "ZONE_IP4:parse_ip4:0:0")
set(AA_qual)
set(AAAA_qual)
set(AAAA_type_print "ZONE_IP6:parse_ip6:0:0")
# Domain name fields, section 3.5.3
#   C: Domain name is compressed
set(N_qual "[CALO]")
set(N_type_print "ZONE_NAME:parse_name:0:0")
set(N_C_qual_print "ZONE_COMPRESSED")
#   A: Domain name represents a mailbox
set(N_A_qual_print "ZONE_MAILBOX")
#   L: Domain name is converted to lower case before DNSSEC validation
set(N_L_qual_print "ZONE_LOWER_CASE")
#   O: Domain name is optional and can only appear as the last field
set(N_L_qual_print "ZONE_OPTIONAL")
# Type fields
set(R_qual "[L]") # R[L] only mentioned in section 3.5.1
set(R_type_print "ZONE_INT16:parse_type:0:0")
set(R_qual_print "ZONE_TYPE")
set(R_L_type_print "ZONE_NSEC:parse_nsec:0:accept_nsec")
set(R_L_qual_print "0")
# String fields
set(S_qual "[MX]")
set(S_type_print "ZONE_STRING:parse_string:0:0")
#   S: Single string preceded by a one-octet length.
#   S[M]: Multiple strings, each stored as a length and string. Must be last!
set(S_M_qual_print "ZONE_SEQUENCE")
#   S[X]: Raw string, without any length bytes. Must be last!
set(S_X_type_print "ZONE_BLOB:parse_text:0:0")
# Base-32 fields
set(B32_qual)
set(B32_type_print "ZONE_BLOB:parse_base32:0:accept_base32")
set(B32_qual_print "ZONE_BASE32")
# Base-64 fields
set(B64_qual)
set(B64_type_print "ZONE_BLOB:parse_base64:0:accept_base64")
set(B64_qual_print "ZONE_BASE64")
# Hex fields
#   X: Binary data. Must be last. May include spaces for readability.
#   X[C]: Stored as a string with a preceding one-octet length.
set(X_qual "[C]")
set(X_type_print "ZONE_BLOB:parse_base16:0:accept_base16")
set(X_qual_print "ZONE_BASE16")
set(X_C_type_print "ZONE_STRING:parse_salt:0:0")
set(X_C_qual_print "ZONE_BASE16")
# Time stamp fields
#   T: Time. Require "YYYYMMDDHHmmSS" notation.
#   T[L]: Time-to-live. Allow for "1h2m3s" notation and disallow use of MSB.
set(T_qual "[L]")
set(T_type_print "ZONE_INT32:parse_time:0:0")
set(T_qual_print "ZONE_TIME")
set(T_L_type_print "ZONE_INT32:parse_ttl:0:0")
set(T_L_qual_print "ZONE_TTL")
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
set(Z_WKS_type_print "ZONE_WKS:parse_wks:0:accept_wks")
set(Z_WKS_qual_print "0")
#set(Z_SVCB_type_print "ZONE_SVC_PARAM")
#set(Z_NXT_type_print "ZONE_NXT")

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
  elseif(line MATCHES "^(${ldh}):(${DIGIT}+)(:[aeioxAEIOX]+)?(${WSP}+.*)?$")
    set(name "${CMAKE_MATCH_1}")
    string(TOLOWER "${name}" lname) # normalize name
    string(TOUPPER "${CMAKE_MATCH_3}" opts)
    # cleanup id
    string(REGEX REPLACE "^0+" "" id "${CMAKE_MATCH_2}")
    # cleanup options
    string(REGEX REPLACE "^:" "" opts "${opts}")
    string(REGEX REPLACE "([a-zA-Z])" "\\1;" opts "${opts}")
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

# Generate descriptor map, indexed by type id
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

  set(desc)
  foreach(type ${types})
    if(NOT type MATCHES "^[^:]+:${id}$")
      continue()
    endif()

    string(REGEX REPLACE ":.*$" "" name "${type}")

    set(fid "0")
    set(fsep "")
    unset(rdata)
    unset(rdatas)
    foreach(field ${_${id}_fields})
      string(REGEX REPLACE ":.*$" "" ftype "${field}")
      string(REGEX REPLACE "^[^:]+:" "" fname "${field}")

      unset(fmap)
      set(fquals "0")
      set(flabels "{ .sorted = NULL, .length = 0 }")
      if(ftype MATCHES "I[0-9]+") # labels
        set(fmap "${${ftype}_type_print}")
        if(_${id}_${fid}_quals)
          set(flabels "{ .sorted = (zone_key_value_t[]){ ")
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
          set(flabels "${flabels}${flabelsep} }, .length = ${flabellen} }")
        endif()
      elseif(_${id}_${fid}_quals) # qualifiers
        set(fquals "")
        set(fqualsep "")
        foreach(fqual ${_${id}_${fid}_quals})
          # Allow custom type based on type+qualifier
          if(${ftype}_${fqual}_type_print AND NOT fmap)
            set(fmap ${${ftype}_${fqual}_type_print})
          endif()
          if(DEFINED ${ftype}_${fqual}_qual_print)
            set(fquals "${fquals}${fqualsep}${${ftype}_${fqual}_qual_print}")
            set(fqualsep " | ")
          endif()
        endforeach()

        # Use generic qualifiers if no type+qualifier map exists
        if(NOT fmap)
          set(fmap "${${ftype}_type_print}")
          if(${ftype}_qual_print)
            set(fquals "${fquals}${fqualsep}${${ftype}_qual_print}")
          endif()
        endif()
      else()
        set(fmap "${${ftype}_type_print}")
        if(DEFINED ${ftype}_qual_print)
          set(fquals "${${ftype}_qual_print}")
        endif()
      endif()

      set(fdesc "NULL")
      if(_${id}_${fid}_desc)
        set(fdesc "${_${id}_${fid}_desc}")
        # FIXME: implement in more robust fashion
        string(REPLACE "\"" "\\\"" fdesc "${fdesc}")
        set(fdesc "\"${fdesc}\"")
      endif()

      if(fmap MATCHES "^([^:]+):([^:]+):([^:]+):([^:]+)$")
        set(ptype "${CMAKE_MATCH_1}")
        set(typed "${CMAKE_MATCH_2}")
        set(generic "${CMAKE_MATCH_3}")
        set(accept "${CMAKE_MATCH_4}")
      else()
        message(FATAL_ERROR "Invalid type mapping for ${ftype} '${fmap}', script error")
      endif()

      # Allow for function overrides
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
        ".base = { "
          ".name = \"${fname}\", "
          ".length = sizeof(\"${fname}\") - 1, "
          ".type = ${ptype}, "
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

    # options
    set(opts)
    if(_${id}_opts)
      set(optsep "")
      foreach(opt ${_${id}_opts})
        if(DEFINED ${opt}_opt_print)
          set(opts "${opts}${optsep}${${opt}_opt_print}")
          set(optsep " | ")
        endif()
      endforeach()
    else()
      set(opts "0")
    endif()

    # description
    set(tdesc "")
    if(_${id}_desc)
      set(tdesc "${_${id}_desc}")
      # FIXME: implement in more robust fashion...
      string(REPLACE "\"" "\\\"" tdesc "${tdesc}")
    endif()

    if(rdata)
      set(rdatas "(struct rdata_descriptor[]){ ${rdata}, { { NULL, 0, 0, 0, { NULL, 0 }, NULL } } }")
    else()
      set(rdatas "(struct rdata_descriptor[]){ { { NULL, 0, 0, 0, { NULL, 0 }, NULL } } }")
    endif()

    string(CONCAT desc
      "{ "
      ".base = { "
        ".name = \"${name}\", "
        ".length = sizeof(\"${name}\") - 1, "
        ".type = ${id}, "
        ".options = ${opts}, "
        ".description = \"${tdesc}\" "
      "}, "
      ".rdata = ${rdatas} }")
    break()
  endforeach()

  if(NOT desc)
    math(EXPR gap "${gap} + 1")
    set(desc "{ .base = { .name = NULL, .length = 0, .options = 0, .description = NULL }, .rdata = NULL }")
  endif()

  set(DESCRIPTORS "${DESCRIPTORS}${sep}${desc}")
  set(sep ",\n")
endforeach()

configure_file("${TEMPLATE}" "${HEADER}" @ONLY)
