#!/usr/bin/env bash
killall -9 zig-miner > /dev/null 2>&1
. h-manifest.conf

CUSTOM_LOG_BASEDIR=`dirname "$CUSTOM_LOG_BASENAME"`
[[ ! -d $CUSTOM_LOG_BASEDIR ]] && mkdir -p $CUSTOM_LOG_BASEDIR

LD_LIBRARY_PATH="./lib:${LD_LIBRARY_PATH}" ./zig-miner $(< $CUSTOM_CONFIG_FILENAME) $@ 2>&1 | tee --append ${CUSTOM_LOG_BASENAME}.log
