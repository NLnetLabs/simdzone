###############
Getting started
###############

|project| is a high performance DNS presentation format parser. |project|
takes care of control entries and deserializes resource record (RR) entries to
wire format. Handling of any special considerations that apply to the data are
delegated to the application to allow for wider applicability and better
performance.

For example, zone files must contain exactly one SOA RR at the top of the zone
and all RRs must be of the same class (see RFC1035 section 5.2). The
application is responsible for enforcing these restrictions so that the
parser itself is equally well suited to parse serialized zone transfers, etc.

The interface is purposely minimalistic and provides two parse functions:

- ``zone_parse`` to parse files.
- ``zone_parse_string`` to parse in-memory data.


To keep track of state, the functions require the application to pass a
``zone_parser_t``, which is initialized on use. ``zone_options_t`` can be
used to configure callbacks, defaults and behavior. Specifying at least an
accept callback function (invoked for each resource record), origin, default
ttl and default class is required.

To avoid memory leaks and improve performance the parser takes a set of
pre-allocated buffers. A ``zone_name_buffer_t`` to store the owner and a
``zone_rdata_buffer_t`` to store RDATA. The ``user_data`` pointer is passed
verbatim to the specified callback function and can be used to communicate
application context.


Parsing zones
-------------

Let's create a simple zone parser to demonstrate |project| usage.

First, we define a function to receives RRs as they're parsed.

.. code-block:: C
   :linenos:
   :lineno-start: 1

   #include <stdio.h>
   #include <stdint.h>
   #include <stdlib.h>

   #include <zone.h>

   struct zone {
     size_t count;
     uint16_t class;
   };

   static const int32_t accept_rr(
     zone_parser_t *parser,
     const zone_name_t *owner,
     uint16_t type,
     uint16_t class,
     uint32_t ttl,
     uint16_t rdlength,
     const uint8_t *rdata,
     void *user_data)
   {
     struct zone *zone = user_data;
     // require first record to be of type SOA
     if (!zone->count) {
       zone->class = class;
       if (type != 6) {
         // use log function to automatically print file and line number
         zone_log(parser, ZONE_ERROR, "First record is not of type SOA");
         return ZONE_SEMANTIC_ERROR;
       }
     } else {
       // require records not to be of type SOA
       if (type == 6) {
         zone_log(parser, ZONE_ERROR, "Extra record of type SOA");
         return ZONE_SEMANTIC_ERROR;
       // require each record uses the same class
       } else if (class != zone->class) {
         zone_log(parser, ZONE_ERROR, "Record not in class " PRIu16, zone->class);
         return ZONE_SEMANTIC_ERROR;
       }
     }

     // authoritative servers would now store RR in a database or similar

     zone->count++;
     return ZONE_SUCCESS;
   }

``zone_log`` is a convenience function that can be used to print location
information with the error message. Returning ``ZONE_SEMANTIC_ERROR`` from
the callback signals the parser an error has occurred and processing must be
halted. |project| defines a number of error codes, but any negative number
will halt the parser. The error code is propagated and eventually returned
as the result of ``zone_parse``.

Next we define a ``main`` function that's called on execution of the program.

.. code-block:: C
   :linenos:
   :lineno-start: 1

   int main(int argc, char *argv[])
   {
     zone_parser_t parser;
     zone_name_buffer_t name;
     zone_rdata_buffer_t rdata;
     zone_buffers_t buffers = { 1, &name, &rdata };
     zone_options_t options = { 0 }; // must be properly initialized

     if (argc != 3) {
       fprintf(stderr, "Usage: %s zone-file origin\n", argv[0]);
       exit(EXIT_FAILURE);
     }

     options.accept.callback = accept_rr;
     options.origin = argv[2];
     options.default_ttl = 3600;
     options.default_class = 1; // IN

     int32_t result;
     struct zone zone = { 0 };

     result = zone_parse(&parser, &options, &buffers, argv[1], &zone);
     if (result < 0) {
       fprintf(stderr, "Could not parse %s\n", argv[1]);
       exit(EXIT_FAILURE);
     }

     printf("parsed %zu records in %s", zone->count, argv[1]);

     return 0;
   }
