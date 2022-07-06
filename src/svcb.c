#include "parser.h"

zone_return_t zone_parse_svc_param(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  assert((tok->code & ZONE_SVC_PARAM) == ZONE_SVC_PARAM);
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_SYNTAX_ERROR;
}

zone_return_t zone_parse_generic_svc_param(
  zone_parser_t *par, const zone_token_t *tok, zone_field_t *fld, void *ptr)
{
  (void)par;
  (void)tok;
  (void)fld;
  (void)ptr;
  return ZONE_SYNTAX_ERROR;
}
