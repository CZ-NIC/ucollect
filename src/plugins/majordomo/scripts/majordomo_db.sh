#!/bin/sh

## Enable/Disable debugging
set -ex

DUMP_FILE_PATH="/tmp/ucollect_majordomo"
DB_PATH="/tmp/majordomo_db"

DB_HOUR_PREFIX="$DB_PATH/majordomo_hourly_"
DB_DAY_PREFIX="$DB_PATH/majordomo_daily_"

if [ ! -e "$DUMP_FILE_PATH"  ]; then
	echo "No dump file found. Is local ucollect running?"
	exit 1
fi

if [ $# -ne 1 ]; then 
	echo "ERROR: Usage: $0 (genhour|genday)"
	exit 1
fi

[ -d $DB_PATH ] || mkdir -p $DB_PATH

CMD="$1"

if [ "$CMD" = "genhour" ]; then
	HOUR_FILE_NAME="$DB_HOUR_PREFIX$(date +"%Y-%m-%d-%H")"
	TMPFILE=$(tempfile --prefix=majordomo)

	## Merge dump file to corresponding hour file should eliminate dump file -
	## we don't want merge the same data again and again
	mv $DUMP_FILE_PATH $TMPFILE
	[ -e "$HOUR_FILE_NAME" ] || touch $HOUR_FILE_NAME
	majordomo_merge.lua $TMPFILE $HOUR_FILE_NAME $HOUR_FILE_NAME
	rm $TMPFILE


elif [ "$CMD" = "genday" ]; then
	DAY=$(date +"%Y-%m-%d")
	DAY_FILE_NAME="$DB_DAY_PREFIX$DAY"
	[ -e "$DAY_FILE_NAME" ] || touch $DAY_FILE_NAME
	for HOUR_FILE in $(ls "$DB_HOUR_PREFIX$DAY-"*); do
		majordomo_merge.lua $HOUR_FILE $DAY_FILE_NAME $DAY_FILE_NAME
		rm $HOUR_FILE
	done
fi
