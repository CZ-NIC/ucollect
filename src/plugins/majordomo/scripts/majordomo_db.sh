#!/bin/sh

if [ $# -ne 1 ]; then
	echo "ERROR: Usage: $0 (downsize|genhour)"
	exit 1
fi

## Settings
DUMP_FILE_PATH="/tmp/ucollect_majordomo"
DOWNSIZE_FILE_PATH="/tmp/majordomo_downsize"
DB_PATH="/tmp/majordomo_db"
KEEP_MONTHLY=12
KEEP_DAILY=60
KEEP_HOURLY=96

## Load UCI configuration
UCIVALUE=$(uci get majordomo.@db[0].path)
[ $? -eq 0 ] && DB_PATH=$UCIVALUE

UCIVALUE=$(uci get majordomo.@statistics[0].store_monthly_files)
[ $? -eq 0 -a "$UCIVALUE" -ge 1 ] && KEEP_MONTHLY="$UCIVALUE"

UCIVALUE=$(uci get majordomo.@statistics[0].store_daily_files)
[ $? -eq 0 -a "$UCIVALUE" -ge 1 ] && KEEP_DAILY="$UCIVALUE"

UCIVALUE=$(uci get majordomo.@statistics[0].store_hourly_files)
[ $? -eq 0 -a "$UCIVALUE" -ge 1 ] && KEEP_HOURLY="$UCIVALUE"

## Compute the rest of constants
DB_HOUR_PREFIX="$DB_PATH/majordomo_hourly_"
DB_DAY_PREFIX="$DB_PATH/majordomo_daily_"
DB_MONTH_PREFIX="$DB_PATH/majordomo_monthly_"
DB_MONTH_ORIGIN_PREFIX="$DB_PATH/majordomo_origin_monthly_"

## Usage
CMD="$1"

## Create DB if not exists
[ -d $DB_PATH ] || mkdir -p $DB_PATH

clean_up() {
	PREFIX="$1"
	KEEP="$2"

	DELETE=$(( $(ls $PREFIX* | wc -l) - $KEEP ))
	[ $DELETE -lt 0 ] && DELETE=0
	DELETE_FILES="$(ls $PREFIX* | sort -n | head -n $DELETE)"
	[ -n "$DELETE_FILES" ] && rm $DELETE_FILES
}

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

	MONTHLY_ORIGIN_FILE_NAME="$DB_MONTH_ORIGIN_PREFIX$(date +"%Y-%m" --date="@$LAST_HOUR")"
	MONTHLY_FILE_NAME="$DB_MONTH_PREFIX$(date +"%Y-%m" --date="@$LAST_HOUR")"
	DAILY_FILE_NAME="$DB_DAY_PREFIX$(date +"%Y-%m-%d" --date="@$LAST_HOUR")"
	HOURLY_FILE_NAME="$DB_HOUR_PREFIX$(date +"%Y-%m-%d-%H" --date="@$LAST_HOUR")"

	[ ! -e "$DAILY_FILE_NAME" ] && touch $DAILY_FILE_NAME
	if [ ! -e "$MONTHLY_FILE_NAME" ]; then
		touch $MONTHLY_FILE_NAME
		echo $LAST_HOUR > $MONTHLY_ORIGIN_FILE_NAME
	fi

	majordomo_merge.lua $DOWNSIZE_FILE_PATH $MONTHLY_FILE_NAME $MONTHLY_FILE_NAME
	majordomo_merge.lua $DOWNSIZE_FILE_PATH $DAILY_FILE_NAME $DAILY_FILE_NAME
	mv $DOWNSIZE_FILE_PATH $HOURLY_FILE_NAME

	clean_up $DB_HOUR_PREFIX $KEEP_HOURLY
	clean_up $DB_DAY_PREFIX $KEEP_DAILY
	clean_up $DB_MONTH_PREFIX $KEEP_MONTHLY
	clean_up $DB_MONTH_ORIGIN_PREFIX $KEEP_MONTHLY

else
	echo "ERROR: undefined command"
	exit 1
fi
