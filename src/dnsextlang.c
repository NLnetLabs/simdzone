/*
 * dnsextlang.c -- generate type descriptors from dnsextlang stanzas
 *
 * Copyright (c) 2022, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

static struct {
  const char *stanzas;
  const char *header;
  const char *format;
  const char *prefix;
  size_t indexed;
} options = {
  NULL,
  NULL,
  "descriptors",
  "",
  255
};

// https://datatracker.ietf.org/doc/html/draft-levine-dnsextlang-12

static struct {
  uint16_t code;
  uint16_t field;
  const char *parse;
  const char *print;
  const char *accept;
} overrides[] = {
  { 11, 1, "parse_wks_protocol", "0", "0" }
};

typedef struct descriptor descriptor_t;
struct descriptor {
  const char *type;
  const char *qualifier;
  const char *parse;
  const char *print;
  const char *accept;
};

typedef struct qualifier qualifier_t;
struct qualifier {
  const char *name;
  descriptor_t descriptor;
};

typedef struct field_type field_type_t;
struct field_type {
  const char *name;
  const qualifier_t *qualifiers;
  descriptor_t descriptor;
};

typedef struct symbol symbol_t;
struct symbol {
  char *name;
  uint32_t value;
};

typedef struct {
  const field_type_t *type;
  char *name;
  char *freetext;
  struct { size_t size; const qualifier_t **data; } qualifiers;
  struct { size_t size; symbol_t *data; } symbols;
} field_t;

typedef struct {
  char *name;
  char *freetext;
  uint16_t type;
  uint32_t options;
  struct { size_t size; field_t *data; } fields;
} record_t;

typedef struct {
  size_t size;
  record_t *data;
} recordset_t;

// dummy, parse symbolic field values instead
static const qualifier_t I_quals[] = {
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t N_quals[] = {
  { "C", { 0, "ZONE_COMPRESSED", "0", "0", "0" } },
  { "A", { 0, "ZONE_MAILBOX",    "0", "0", "0" } },
  { "L", { 0, "ZONE_LOWER_CASE", "0", "0", "0" } },
  { "O", { 0, "ZONE_OPTIONAL",   "0", "0", "0" } },
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t S_quals[] = {
  { "M", { 0, "ZONE_SEQUENCE",   "0", "0", "0" } },
  { "X", { "ZONE_BLOB", "0",     "0", "0", "0" } },
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t X_quals[] = {
  { "C", { "ZONE_STRING", "ZONE_BASE16", "parse_salt", "0", "0" } },
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t T_quals[] = {
  { "L", { "ZONE_INT32", "0", "parse_ttl", "0", "0" } },
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t Z_quals[] = {
  { "WKS",  { "ZONE_WKS",  "0", "parse_wks",  "0",  "accept_wks" } },
#if 0
  { "NSAP", { } },
  { "NXT", { } },
  { "A6P", { } },
  { "A6S", { } },
  { "APL", { } },
  { "IPSECKEY", { } },
  { "HIPHIT", { } },
  { "HIPPK", { } },
#endif
  { "SVCB", { "ZONE_SVC_PARAM", "0", "parse_svc_param", "0", "0" } },
  { 0, { 0, 0, 0, 0, 0 } }
};

static const qualifier_t R_quals[] = {
  { "L",    { "ZONE_NSEC", "0", "parse_nsec", "0", "accept_nsec" } }
};

// field types as defined in section 3.1 (R mentioned in section 3.5.1)
static const field_type_t field_types[] = {
  { "I1",   I_quals, { "ZONE_INT8",   0,             "parse_int8",  "0", "0" } },
  { "I2",   I_quals, { "ZONE_INT16",  0,             "parse_int16", "0", "0" } },
  { "I4",   I_quals, { "ZONE_INT32",  0,             "parse_int32", "0", "0" } },
  { "A",    0,       { "ZONE_IP4",    0,             "parse_ip4",   "0", "0" } },
#if 0
  { "AA", },
#endif
  { "AAAA", 0,       { "ZONE_IP6",    0,             "parse_ip6",    "0", "0" } },
  { "N",    N_quals, { "ZONE_NAME",   0,             "parse_name",   "0", "0" } },
  { "S",    S_quals, { "ZONE_STRING", 0,             "parse_string", "0", "0" } },
  { "B32",  0,       { "ZONE_BLOB",   "ZONE_BASE32", "parse_base32", "0", "0" } },
  { "B64",  0,       { "ZONE_BLOB",   "ZONE_BASE64", "parse_base64", "0", "0" } },
  { "X",    X_quals, { "ZONE_BLOB",   "ZONE_BASE16", "parse_base16", "0", "0" } },
  { "T",    T_quals, { "ZONE_INT32",  "ZONE_TIME",   "parse_time",   "0", "0" } },
  { "Z",    Z_quals, { 0,             "0",           "0",            "0", "0" } },
  { "R",    R_quals, { "ZONE_INT16",  "ZONE_TYPE",   "parse_type",   "0", "0" } }
};

#define BAD_RECORD (-1)
#define BAD_FIELD (-2)
#define NO_MEMORY (-3)

static int sort_symbols(const void *p1, const void *p2)
{
  const symbol_t *s1 = p1, *s2 = p2;
  return strcmp(s1->name, s2->name);
}

static int parse_symbols(field_t *fld, char *str)
{
  size_t cnt;
  char *saveptr = NULL, *tok;

  cnt = 1;
  for (char *ptr=str; *ptr; ptr++)
    if (*ptr == ',')
      cnt++;

  if (!(fld->symbols.data = calloc(cnt, sizeof(*fld->symbols.data))))
    return NO_MEMORY;
  fld->symbols.size = cnt;

  cnt = 0;
  for (char *ptr=str; (tok=strtok_r(ptr, ",", &saveptr)); ptr=NULL) {
    size_t len = 0;
    for (; tok[len] && tok[len] != '='; len++)
      ;
    if (tok[len] != '=')
      return BAD_RECORD;
    char *end;
    unsigned long lng = strtoul(&tok[len+1], &end, 10);
    if (*end != '\0')
      return BAD_RECORD;
    if (!(fld->symbols.data[cnt].name = strndup(tok, len)))
      return NO_MEMORY;
    fld->symbols.data[cnt].value = (uint32_t)lng;
    cnt++;
  }

  assert(fld->symbols.size <= cnt);
  qsort(fld->symbols.data, fld->symbols.size, sizeof(symbol_t), sort_symbols);

  return 0;
}

static int parse_qualifiers(field_t *fld, char *str)
{
  size_t cnt;
  char *saveptr = NULL, *tok;
  const field_type_t *ftype;

  assert(fld->type);
  ftype = fld->type;

  cnt = 1;
  for (char *ptr=str; *ptr; ptr++)
    if (*ptr == ',')
      cnt++;

  if (!(fld->qualifiers.data = calloc(cnt, sizeof(*fld->qualifiers.data))))
    return NO_MEMORY;
  fld->qualifiers.size = cnt;

  cnt = 0;
  for (char *ptr=str; (tok=strtok_r(ptr, ",", &saveptr)); ptr=NULL) {
    const qualifier_t *qual = NULL;
    for (size_t i=0; ftype->qualifiers[i].name; i++) {
      if (strcasecmp(tok, ftype->qualifiers[i].name) != 0)
        continue;
      qual = &ftype->qualifiers[i];
      break;
    }
    if (!qual)
      return BAD_RECORD;
    fld->qualifiers.data[cnt++] = qual;
  }

  assert(fld->qualifiers.size <= cnt);

  return 0;
}

static int parse_field(field_t *fld, char *str, size_t len)
{
  size_t cur = 0, end;
  const char *ftype, *name = "", *freetext;
  char *quals = NULL;

  (void)len;

  // drop any leading spaces
  for (; isspace(str[cur]); cur++)
    ;
  ftype = &str[cur];

  // skip ahead to qualifiers, name or freetext
  for (; str[cur] && str[cur] != ':' && str[cur] != '['; cur++)
    ;

  // qualifiers
  if (str[cur] == '[') {
    str[cur++] = '\0';
    quals = str + cur;
    for (; str[cur] && str[cur] != ']'; cur++)
      ;
    if (str[cur] != ']')
      return BAD_RECORD;
    str[cur++] = '\0';
  }

  // name
  if (str[cur] == ':') {
    str[cur++] = '\0';
    name = str + cur;
    for (; str[cur] && !isspace(str[cur]); cur++)
      ;
    if (isspace(str[cur]))
      str[cur++] = '\0';
  }

  // drop any spaces
  for (; isspace(str[cur]); cur++)
    ;
  // freetext
  freetext = &str[cur];
  // drop any trailing spaces
  end = cur;
  for (; str[cur]; cur++)
    if (!isspace(str[cur]))
      end = cur+1;
  str[end] = '\0';


  for (size_t i=0, n=sizeof(field_types)/sizeof(field_types[0]); i < n; i++) {
    if (strcasecmp(ftype, field_types[i].name) != 0)
      continue;
    fld->type = &field_types[i];
    break;
  }

  if (!fld->type)
    return BAD_RECORD;
  if (name && !(fld->name = strdup(name)))
    return NO_MEMORY;
  if (freetext && !(fld->freetext = strdup(freetext)))
    return NO_MEMORY;

  if (!quals)
    return 0;
  else if (fld->type->qualifiers == I_quals)
    return parse_symbols(fld, quals);
  else if (fld->type->qualifiers)
    return parse_qualifiers(fld, quals);
  else
    return BAD_RECORD;
}

#define IN (1<<0)
#define ANY (1<<1)
#define OBSOLETE (1<<2)
#define EXPERIMENTAL (1<<3)

static int parse_record(record_t *rec, char *str, size_t len)
{
  char *ptr = NULL;
  uint16_t type;
  uint32_t opts = 0;
  size_t cnt = 0, namelen = 0;

  assert(len);

  if (!isalpha(str[cnt]))
    return BAD_RECORD;

  for (++cnt; cnt < len; cnt++) {
    if (isalnum(str[cnt]) || str[cnt] == '-')
      continue;
    if (str[cnt] == ':')
      break;
    return BAD_RECORD;
  }

  assert(str[cnt] == ':');
  namelen = cnt;

  unsigned long lng;
  if (!(lng = strtoul(&str[cnt+1], &ptr, 10)) || lng > UINT16_MAX)
    return BAD_RECORD;
  type = (uint16_t)lng;

  cnt = ptr - str;
  if (str[cnt] == ':') {
    for (++cnt; cnt < len; cnt++) {
      if (str[cnt] == 'X')
        opts |= 0; // ignore
      else if (str[cnt] == 'I')
        opts |= IN;
      else if (str[cnt] == 'A')
        opts |= ANY;
      else if (str[cnt] == 'O')
        opts |= OBSOLETE;
      else if (str[cnt] == 'E')
        opts |= EXPERIMENTAL;
      else if (isspace(str[cnt]) || str[cnt] == '\0')
        break;
      else
        return BAD_RECORD;
    }
  }

  // drop any spaces
  for (; isspace(str[cnt]); cnt++)
    ;
  // freetext
  const char *freetext = &str[cnt];
  // drop any trailing spaces
  size_t end = cnt;
  for (; str[cnt]; cnt++)
    if (!isspace(str[cnt]))
      end = cnt+1;
  str[end] = '\0';

  if (!(rec->name = strndup(str, namelen)))
    return NO_MEMORY;
  if (!(rec->freetext = strdup(freetext)))
    return NO_MEMORY;
  rec->type = type;
  rec->options = opts;
  return 0;
}

static void free_records(recordset_t *recs)
{
  // iterate 'n stuff
  (void)recs;
  return;
}

static ssize_t get_records(recordset_t *recs, FILE *stream)
{
  int err = 0;
  char *str = NULL;
  size_t len = 0, line = 0;
  enum { INITIAL, RECORD } state = INITIAL;
  record_t *rec = NULL;

  while (getline(&str, &len, stream) != -1) {
    line++;

    // ignore leading whitespace
    char *ptr = str;
    while (*ptr && isspace(*ptr))
      ptr++;
    // discard lines where the first character is a '#'
    if (!*ptr || *ptr == '#')
      continue;

    switch (state) {
      case INITIAL: {
        record_t *data;
        const size_t size = (recs->size + 1) * sizeof(*data);
        if (!(data = realloc(recs->data, size)))
          goto no_memory;
        recs->size++;
        recs->data = data;
        rec = &data[recs->size - 1];
        memset(rec, 0, sizeof(*rec));
        if ((err = parse_record(rec, str, len)) < 0)
          goto error;
        state = RECORD;
      } break;
      case RECORD: {
        if (ptr != str) {
          assert(rec);

          field_t *data;
          const size_t size = (rec->fields.size + 1) * sizeof(*data);
          if (!(data = realloc(rec->fields.data, size)))
            goto no_memory;
          rec->fields.size++;
          rec->fields.data = data;
          memset(&data[rec->fields.size - 1], 0, sizeof(data[size - 1]));
          if ((err = parse_field(&data[rec->fields.size - 1], str, len)) < 0)
            goto error;
        } else {
          record_t *data;
          const size_t size = (recs->size + 1) * sizeof(*data);
          if (!(data = realloc(recs->data, size)))
            goto no_memory;
          recs->size++;
          recs->data = data;
          rec = &data[recs->size - 1];
          memset(rec, 0, sizeof(*rec));
          if ((err = parse_record(rec, str, len)) < 0)
            goto error;
        }
      } break;
    }
  }

  return 0;
no_memory:
  err = NO_MEMORY;
error:
  if (str)
    free(str);
  return err;
}

static int sortbyname(const void *p1, const void *p2)
{
  const record_t *r1 = p1, *r2 = p2;
  assert(r1->name);
  assert(r2->name);
  return strcmp(r1->name, r2->name);
}

// FIXME: rename to print_<something>
static int generate_types(FILE *fout, recordset_t *recs)
{
  qsort(recs->data, recs->size, sizeof(*recs->data), &sortbyname);

  if (fputs("static const zone_key_value_t types[] = {\n", fout) == EOF)
    return -1;

  for (size_t i=0; i < recs->size; i++) {
    if (i && fputs(",\n", fout) == EOF)
      return -1;
    uint16_t code = recs->data[i].type;
    const char *name = recs->data[i].name;
    fprintf(fout, "  { \"%s\", sizeof(\"%s\") - 1, %u }", name, name, code);
  }

  if (fputs("\n};\n", fout) == EOF)
    return -1;

  return 0;
}

static int sortbycode(const void *p1, const void *p2)
{
  const record_t *r1 = p1, *r2 = p2;
  return r1->type - r2->type;
}

static int print_grammar(FILE *fout, recordset_t *recs)
{
  const char *rsep = "  ";
  qsort(recs->data, recs->size, sizeof(*recs->data), &sortbycode);

  if (fputs("static const struct type_descriptor descriptors[] = {\n", fout) == EOF)
    return -1;

  // descriptors for the most common record types must be directly accessible
  // using the corresponding type code for performance reasons. to limit the
  // amount of memory required, no dummy entries are generated for types
  // beyond the user configurable maximum if the array becomes sparse.
  for (uint16_t code = 0, index = 0; code < options.indexed || index < recs->size; code++) {
    if (code == recs->data[index].type) {
      const record_t *record = &recs->data[index++];
      const char *name = record->name;
      const char *freetext = record->freetext;
      const char *class = "ZONE_IN";
      const char *options = "";
      if (record->options & ANY)
        class = "ZONE_ANY";
      if ((record->options & OBSOLETE) && (record->options & EXPERIMENTAL))
        options = " | ZONE_OBSOLETE | ZONE_EXPERIMENTAL";
      else if ((record->options & OBSOLETE))
        options = " | ZONE_OBSOLETE";
      else if ((record->options & EXPERIMENTAL))
        options = " | ZONE_EXPERIMENTAL";

#define TYPEHDRFMT                 \
  "%s{ .base = { "                 \
    ".name = \"%s\", "             \
    ".length = sizeof(\"%s\")-1, " \
    ".type = %"PRIu16", "          \
    ".options = %s%s, "            \
    ".description = \"%s\", "      \
  "}, .rdata = (struct rdata_descriptor[]) { "

      fprintf(fout, TYPEHDRFMT, rsep, name, name, code, class, options, freetext);

      for (size_t fieldno=0; fieldno < record->fields.size; fieldno++) {
        const field_t *fld = &record->fields.data[fieldno];
        const descriptor_t *dsc = &fld->type->descriptor;

        // dnsextlang leans towards describing the data as it is presented in
        // the zone file. the parser abstracts the text representation and
        // defines types by how they are presented on the wire. descriptors
        // may change completely if a certain type of qualifier occurs
        for (size_t cnt=0; cnt < fld->qualifiers.size; cnt++) {
          if (fld->qualifiers.data[cnt]->descriptor.type)
            dsc = &fld->qualifiers.data[cnt]->descriptor;
        }

        char qualifiers[64] = "0";
        {
          char *str = qualifiers;
          size_t cnt = 0, len = 0, sz = sizeof(qualifiers);
          ssize_t inc = 0;
          const char *qual = dsc->qualifier;
          if (qual && (inc = snprintf(str, sz, "%s", qual)) < 0)
            return -1;
          len += (size_t)inc;
          for (; cnt < fld->qualifiers.size; cnt++) {
            const char *sep = len ? " | " : "";
            if (fld->qualifiers.data[cnt]->descriptor.type)
              continue;
            if (!fld->qualifiers.data[cnt]->descriptor.qualifier)
              continue;
            qual = fld->qualifiers.data[cnt]->descriptor.qualifier;
            if ((inc = snprintf(str+len, sz-len, "%s%s", sep, qual)) < 0)
              return -1;
            len += (size_t)inc;
            if (len > sz)
              return -1;
          }
        }

        char symbols[4096];
        if (!fld->symbols.size) {
          snprintf(symbols, sizeof(symbols), "{ .sorted = NULL, .length = 0 }");
        } else {
#define SYMHDRFMT "{ .sorted = (zone_key_value_t[]){ "
#define SYMFMT "%s{ \"%s\", sizeof(\"%s\")-1, %"PRIu32" }"
#define SYMFTRFMT " }, .length = %zu }"
          char *str = symbols;
          size_t cnt = 0, len = 0, sz = sizeof(symbols);
          ssize_t inc;
          if ((inc = snprintf(str, sz, SYMHDRFMT)) < 0)
            return -1;
          len += (size_t)inc;
          for (; cnt < fld->symbols.size; cnt++) {
            const char *sep = cnt ? ", " : "";
            const char *sym = fld->symbols.data[cnt].name;
            const uint32_t num = fld->symbols.data[cnt].value;
            if ((inc = snprintf(str+len, sz-len, SYMFMT, sep, sym, sym, num)) < 0)
              return -1;
            len += (size_t)inc;
            if (len > sz)
              return -1;
          }
          if ((inc = snprintf(str+len, sz-len, SYMFTRFMT, cnt)) < 0)
            return -1;
          len += (size_t)inc;
          if (len > sz)
            return -1;
        }

#define RDATAFMT                     \
  "%s{ .base = { "                   \
    ".name = \"%s\", "               \
    ".length = sizeof(\"%s\") - 1, " \
    ".type = %s, "                   \
    ".qualifiers = %s, "             \
    ".description = \"%s\", "        \
    ".labels = %s "                  \
  "}, "                              \
  ".parse = %s, "                    \
  ".print = %s, "                    \
  ".accept = %s "                    \
  "}"

        const char *parse = dsc->parse;
        const char *print = dsc->print;
        const char *accept = dsc->accept;
        for (size_t x=0, n=sizeof(overrides)/sizeof(overrides[0]); x < n; x++) {
          if (code != overrides[x].code || fieldno != overrides[x].field)
            continue;
          parse = overrides[x].parse;
          print = overrides[x].print;
          accept = overrides[x].accept;
          break;
        }

        name = fld->name ? fld->name : "";
        freetext = fld->freetext ? fld->freetext : "";
        const char *type = dsc->type;
        fprintf(fout, RDATAFMT, fieldno ? ", " : "", name, name, type, qualifiers, freetext, symbols,
          parse, print, accept);
      }

#define TYPEFTRFMT \
  ", { { NULL, 0, 0, 0, { NULL, 0 }, NULL }, 0, 0, 0 } } }"

      fprintf(fout, TYPEFTRFMT);
    } else if (code < options.indexed) {
      fprintf(fout, "%s{ .base = { .name = NULL, .length = 0, .options = 0, .description = NULL }, .rdata = NULL }", rsep);
    }

    rsep = ",\n  ";
  }

  if (fputs("\n};\n", fout) == EOF)
    return -1;
  return 0;
}

static int print_type_codes(FILE *fout, recordset_t *recs)
{
  char prefix[512] = "";

  qsort(recs->data, recs->size, sizeof(*recs->data), &sortbycode);
  (void)snprintf(prefix, sizeof(prefix), "%s", options.prefix);

  for (char *ptr=prefix; *ptr; ptr++) {
    if (isalnum((unsigned char)*ptr))
      *ptr = toupper(*ptr);
    else
      *ptr = '_';
  }

  for (size_t cnt=0; cnt < recs->size; cnt++) {
    uint16_t code = recs->data[cnt].type;
    const char *name = recs->data[cnt].name;
    fprintf(fout, "#define %s%s (%"PRIu16")\n", prefix, name, code);
  }

  return 0;
}

static void usage(const char *prog)
{
  fprintf(stderr, "Usage: %s [OPTIONS] FORMAT STANZAS OUTPUT\n", prog);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
  int opt;
  FILE *fin = NULL, *fout = NULL;
  ssize_t err = 0;
  recordset_t recs = { 0, NULL };

  while ((opt = getopt(argc, argv, "i:p:")) != -1) {
    switch (opt) {
      case 'p': // prefix used for variables and/or defines
        options.prefix = optarg;
        break;
      case 'i':
        options.indexed = atoi(optarg);
        break;
      default:
        usage(argv[0]);
    }
  }

  if (optind > argc - 3)
    usage(argv[0]);

  options.format = argv[optind];
  options.stanzas = argv[optind+1];
  options.header = argv[optind+2];

  const char *filename;
  const char *purpose;
  char define[1024];

  if (strcasecmp(options.format, "GRAMMAR") == 0) {
    filename = "grammar.h";
    purpose = "Zone file grammar";
  } else if (strcasecmp(options.format, "TYPE-CODES") == 0) {
    filename = "types.h";
    purpose = "RR type codes";
  } else if (strcasecmp(options.format, "TYPE-TABLE") == 0) {
    filename = "types.h";
    purpose = "RR type code lookup table";
  } else {
    usage(argv[0]);
  }

  if (!(fin = fopen(options.stanzas, "rb"))) {
    fprintf(stderr, "Cannot open %s for reading\n", options.stanzas);
    goto err_stanzas;
  }

  if (strcmp(options.header, "-") == 0) {
    fout = stdout;
  } else if (!(fout = fopen(options.header, "wb"))) {
    fprintf(stderr, "Cannot open %s for writing\n", options.header);
    goto err_header;
  }

  if ((err = get_records(&recs, fin)) < 0) {
    if (err == BAD_RECORD)
      fprintf(stderr, "Bad record\n");
    else if (err == BAD_FIELD)
      fprintf(stderr, "Bad field\n");
    else
      fprintf(stderr, "No memory\n");
    goto err_records;
  }

  if (strcmp(options.header, "-") != 0) {
    filename = options.header;
    for (const char *ptr=filename; *ptr; ptr++) {
      if (*ptr == '/' || *ptr == '\\')
        filename = ptr+1;
    }
  }

  snprintf(define, sizeof(define), "%s%s", options.prefix, filename);
  for (char *ptr=define; *ptr; ptr++) {
    if (isalnum(*ptr))
      *ptr = toupper((unsigned char)*ptr);
    else
      *ptr = '_';
  }

#define HEADER                                              \
"/*\n"                                                      \
" * %s -- %s generated by %s\n"                             \
" *\n"                                                      \
" * Copyright (c) 2022, NLnet Labs. All rights reserved.\n" \
" *\n"                                                      \
" * See LICENSE for the license.\n"                         \
" *\n"                                                      \
" */\n"                                                     \
"#ifndef %s\n"                                              \
"#define %s\n"                                              \
"\n"

  if (fprintf(fout, HEADER, filename, purpose, argv[0], define, define) < 0) {
    fprintf(stderr, "Cannot generate header\n");
    goto err_output;
  }

  if (strcasecmp(options.format, "TYPE-CODES") == 0) {
    print_type_codes(fout, &recs);
  } else if (strcasecmp(options.format, "TYPE-TABLE") == 0) {
    if (generate_types(fout, &recs) != 0) {
      fprintf(stderr, "Cannot generate types\n");
      goto err_output;
    }
  } else if (strcasecmp(options.format, "GRAMMAR") == 0) {
    if (print_grammar(fout, &recs) != 0) {
      fprintf(stderr, "Cannot generate grammar\n");
      goto err_output;
    }
  }

#define FOOTER   \
"\n"             \
"#endif // %s\n"
  if (fprintf(fout, FOOTER, define) < 0) {
    fprintf(stderr, "Cannot generate footer\n");
    goto err_output;
  }

  fclose(fin);
  if (fout != stdout)
    fclose(fout);
  free_records(&recs);
  return 0;
err_output:
//err_format:
err_records:
  free_records(&recs);
err_header:
  fclose(fin);
err_stanzas:
  exit(EXIT_FAILURE);
}
