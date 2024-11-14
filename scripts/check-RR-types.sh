#!/bin/sh

if [ -e ../include/zone.h ]; then
	ZONE_H="../include/zone.h"
elif  [ -e include/zone.h ]; then
	ZONE_H="include/zone.h"
else
	>&2 echo "Could not find zone.h"
	exit 1
fi
TOIMPLEMENT=0

TEMPFILE=`mktemp --suffix=.xml`
wget --quiet --output-document $TEMPFILE https://www.iana.org/assignments/dns-parameters/dns-parameters.xml
#TEMPFILE=dns-parameters.xml
RECORDS=`xmlstarlet select --template --match "/_:registry/_:registry[@id='dns-parameters-4']/_:record[((_:value>0 and _:value!=41 and _:value<128) or (_:value>255 and _:value<65535)) and _:type!='Unassigned']" --value-of "_:type" --output "#" --value-of "_:value" --output "#" --value-of "_:xref[last()]/@type" --output "#" --value-of "_:xref[last()]/@data" --output "#" --value-of "_:file[@type='template']" --nl ${TEMPFILE}`
rm ${TEMPFILE}
for RECORD in ${RECORDS}
do
	TYPE=`echo ${RECORD} | awk -F# '{ print $1 }'`
	VALUE=`echo ${RECORD} | awk -F# '{ print $2 }'`
	RECORD_TYPE=`echo ${RECORD} | awk -F# '{ print $3 }'`
	RECORD_REF=`echo ${RECORD} | awk -F# '{ print $4 }'`
	TEMPLATE=`echo ${RECORD} | awk -F# '{ print $5 }'`
	case "${RECORD_TYPE}" in
	text)   continue;;
	rfc)    RECORD_REF="https://www.rfc-editor.org/rfc/${RECORD_REF}.html";;
	draft)  RECORD_REF="https://datatracker.ietf.org/doc/${RECORD_REF}";;
	person) RECORD_REF="https://www.iana.org/assignments/dns-parameters/${TEMPLATE}";;
	esac
	if ! grep -q "^#define ZONE_TYPE_${TYPE} " ${ZONE_H} ; then
		echo "${TYPE}	${VALUE}	${RECORD_REF}"
		TOIMPLEMENT=`expr ${TOIMPLEMENT} + 1`
	fi
done
if [ $TOIMPLEMENT -eq 0 ]; then
        echo "All RR types implemented"
fi
exit ${TOIMPLEMENT}

