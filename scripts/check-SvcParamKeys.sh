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
wget --quiet --output-document $TEMPFILE https://www.iana.org/assignments/dns-svcb/dns-svcb.xml
#TEMPFILE=dns-svcb.xml
RECORDS=`xmlstarlet select --template --match "/_:registry/_:registry[@id='dns-svcparamkeys']/_:record[_:value<65280]" --value-of "_:name" --output "#" --value-of "_:value" --output "#" --value-of "_:xref[last()]/@type" --output "#" --value-of "_:xref[last()]/@data" --nl ${TEMPFILE}`
rm ${TEMPFILE}
for RECORD in ${RECORDS}
do
	NAME=`echo ${RECORD} | awk -F# '{ print $1 }'`
	VALUE=`echo ${RECORD} | awk -F# '{ print $2 }'`
	RECORD_TYPE=`echo ${RECORD} | awk -F# '{ print $3 }'`
	RECORD_REF=`echo ${RECORD} | awk -F# '{ print $4 }'`
	case "${RECORD_TYPE}" in
	text)   continue;;
	rfc)    RECORD_REF="https://www.rfc-editor.org/rfc/${RECORD_REF}.html";;
	draft)  RECORD_REF="https://datatracker.ietf.org/doc/${RECORD_REF}";;
	esac
	MATCH_NAME=`echo $NAME | tr a-z- A-Z_`
	if ! grep -q "^#define ZONE_SVC_PARAM_KEY_${MATCH_NAME} " ${ZONE_H} ; then
		echo "${NAME}	${VALUE}	${RECORD_REF}"
		TOIMPLEMENT=`expr ${TOIMPLEMENT} + 1`
	fi
done
if [ $TOIMPLEMENT -eq 0 ]; then
	echo "All SvcParamKeys implemented"
fi
exit ${TOIMPLEMENT}

