#!/bin/sh

DUMP_FILE_PATH="/tmp/ucollect_majordomo"
DB_PATH="/tmp/majordomo_db"

DB_HOUR_PREFIX="$DB_PATH/majordomo_hourly_"
DB_DAY_PREFIX="$DB_PATH/majordomo_daily_"

if [ $# -ne 1 ]; then 
	echo "ERROR: Usage: $0 (genhour|genday)"
	exit 1
fi

## Try to get different value from uci config
TRYUCIPATH=$(uci get majordomo.@db[0].path)
[ $? -eq 0 ] && DB_PATH=$TRYUCIPATH

## Create DB if not exists
[ -d $DB_PATH ] || mkdir -p $DB_PATH

CMD="$1"

if [ "$CMD" = "genhour" ]; then
	HOUR_FILE_NAME="$DB_HOUR_PREFIX$(date +"%Y-%m-%d-%H")"
	## OK, OpenWrt doesn't have tempfile... grrr
	#TMPFILE=$(tempfile --prefix=majordomo)
	TMPFILE="/tmp/majordomo_tempfile_$$_$(date +"%s")"

	## Merge dump file to corresponding hour file should eliminate dump file -
	## we don't want merge the same data again and again
	mv $DUMP_FILE_PATH $TMPFILE
	[ -e "$HOUR_FILE_NAME" ] || touch $HOUR_FILE_NAME
	majordomo_merge.lua $TMPFILE $HOUR_FILE_NAME $HOUR_FILE_NAME
	rm $TMPFILE


elif [ "$CMD" = "genday" ]; then
	for DAY in $(ls $DB_HOUR_PREFIX* | sed "s/.*\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\)-[0-9]\{2\}/\1/" | uniq); do
		DAY_FILE_NAME="$DB_DAY_PREFIX$DAY"
		[ -e "$DAY_FILE_NAME" ] || touch $DAY_FILE_NAME
		for HOUR_FILE in $(ls "$DB_HOUR_PREFIX$DAY-"*); do
			majordomo_merge.lua $HOUR_FILE $DAY_FILE_NAME $DAY_FILE_NAME
			rm $HOUR_FILE
		done
	done
fi
