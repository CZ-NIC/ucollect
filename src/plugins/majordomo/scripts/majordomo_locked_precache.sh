#!/bin/sh

LOCK_DIR="/tmp/majordomo_precache_lock"

if mkdir "$LOCK_DIR" 2>/dev/null; then
	trap 'kill $PID ; rm -rf "$LOCK_DIR" ; exit 2' INT QUIT TERM ABRT HUP ILL TRAP BUS FPE SEGV
	timeout 45m majordomo_cache.lua precache &
	PID=$!
	wait
	STATUS=$?
	rm -rf "$LOCK_DIR"
	exit $STATUS
fi
