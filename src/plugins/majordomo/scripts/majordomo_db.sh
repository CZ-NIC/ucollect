#!/bin/sh

if [ $# -ne 1 ]; then
	echo "ERROR: Usage: $0 (genhour|genday)"
	exit 1
fi

## Try to get different value from uci config
TRYUCIPATH=$(uci get majordomo.@db[0].path)
[ $? -eq 0 ] && DB_PATH=$TRYUCIPATH

## Create DB if not exists
[ -d $DB_PATH ] || mkdir -p $DB_PATH

DUMP_FILE_PATH="/tmp/ucollect_majordomo"
DOWNSIZE_FILE_PATH="/tmp/majordomo_downsize"
DB_PATH="/tmp/majordomo_db"

DB_HOUR_PREFIX="$DB_PATH/majordomo_hourly_"
DB_DAY_PREFIX="$DB_PATH/majordomo_daily_"
DB_MONTH_PREFIX="$DB_PATH/majordomo_monthly_"

CMD="$1"

if [ "$CMD" = "downsize" ]; then
	## OK, OpenWrt doesn't have tempfile... grrr
	#TMPFILE=$(tempfile --prefix=majordomo)
	TMPFILE="/tmp/majordomo_tempfile_$$_$(date +"%s")"

	## Merge dump file to corresponding downsize file should eliminate dump file -
	## we don't want merge the same data again and again
	mv $DUMP_FILE_PATH $TMPFILE
	[ "$?" -ne 0 ] && exit 0
	[ -e "$DOWNSIZE_FILE_PATH" ] || touch $DOWNSIZE_FILE_PATH

	majordomo_merge.lua $TMPFILE $DOWNSIZE_FILE_PATH $DOWNSIZE_FILE_PATH
	if [ "$?" -eq 0 ]; then
		rm $TMPFILE
	else
		## Lose one minute is better than lose 5 minutes
		mv $TMPFILE $DUMP_FILE_PATH
	fi

elif [ "$CMD" = "genhour" ]; then
	NOW=$(date +"%s")
	LAST_HOUR=$(( $NOW - 3600 ))

	MONTHLY_FILE_NAME="$DB_MONTH_PREFIX$(date +"%Y-%m" --date="@$LAST_HOUR")"
	DAILY_FILE_NAME="$DB_DAY_PREFIX$(date +"%Y-%m-%d" --date="@$LAST_HOUR")"
	HOURLY_FILE_NAME="$DB_HOUR_PREFIX$(date +"%Y-%m-%d-%H" --date="@$LAST_HOUR")"

	[ -e "$MONTHLY_FILE_NAME" ] || touch $MONTHLY_FILE_NAME
	[ -e "$DAILY_FILE_NAME" ] || touch $DAILY_FILE_NAME

	majordomo_merge.lua $DOWNSIZE_FILE_PATH $MONTHLY_FILE_NAME $MONTHLY_FILE_NAME
	majordomo_merge.lua $DOWNSIZE_FILE_PATH $DAILY_FILE_NAME $DAILY_FILE_NAME
	mv $DOWNSIZE_FILE_PATH $HOURLY_FILE_NAME
fi
