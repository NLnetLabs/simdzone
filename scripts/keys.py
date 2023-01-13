#!/usr/bin/python
#
# keys.py -- generate key material for fast identifier table
#
# Copyright (c) 2023, NLnet Labs. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#

classes = [ 'CH', 'CS', 'HS', 'IN' ]

types = [
  'A', 'A6', 'AAAA', 'AFSDB', 'APL',
  'CAA', 'CDS', 'CDNSKEY', 'CERT', 'CNAME', 'CSYNC',
  'DNAME', 'DS', 'DNSKEY', 'DHCID', 'DLV',
  'EUI48', 'EUI64',
  'GPOS',
  'HINFO', 'HIP', 'HTTPS',
  'IPSECKEY', 'ISDN',
  'KEY', 'KX',
  'L32', 'L64', 'LOC', 'LP',
  'MB', 'MD', 'MF', 'MG', 'MINFO', 'MR', 'MX',
  'NAPTR', 'NID', 'NS', 'NSAP', 'NSAP-PTR', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'NULL', 'NXT',
  'OPENPGPKEY', 'OPT',
  'PTR', 'PX',
  'RP', 'RRSIG', 'RT',
  'SIG', 'SMIMEA', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB',
  'TXT', 'TLSA',
  'URI',
  'WKS',
  'X25',
  'ZONEMD',
]

keys = [[0 for x in range(255)] for y in range(32)]

for c in classes:
  k = ((ord(c[0])  & 0xdf) - 0x41) & 0x1f
  h = ((ord(c[-1]) & 0xdf))
  h = (h * 0x07)
  h = (h + len(c)) & 0xff
  if keys[k][h]:
    print(f'class: {c}, key: {k}, hash: {h} (collision)')
  else:
    print(f'class: {c}, key: {k}, hash: {h}')
  keys[k][h] = True

for c in types:
  k = ((ord(c[0])  & 0xdf) - 0x41) & 0x1f
  h = ((ord(c[-1]) & 0xdf))
  h = (h * 0x07)
  h = (h + len(c)) & 0xff
  if keys[k][h]:
    print(f'type: {c}, key: {k}, hash: {h} (collision)')
  else:
    print(f'type: {c}, key: {k}, hash: {h}')
  keys[k][h] = True
