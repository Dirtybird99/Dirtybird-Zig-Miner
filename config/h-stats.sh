#!/usr/bin/env bash
. "${HIVE_MANIFEST:-/hive/miners/custom/zig-miner/h-manifest.conf}"

# zig-miner has no HTTP stats API; it prints a live status line to the log via
# newline records (or carriage-return updates on an interactive terminal):
#   [DIRTYBIRD] <X.XX> KH/s (<Y.YY> KH/s avg) | Height:<n> |
#   Miniblocks:<accepted> | Blocks:<n> | REJ:<rejected> | Diff:<n> | HH:MM:SS
# We scrape the freshest canonical record for the HiveOS dashboard.

LOG="${CUSTOM_LOG_BASENAME}.log"

khs=0
uptime=0
acc=0
rej=0

if [[ -f $LOG ]]; then
    line=$(tail -c 8192 "$LOG" 2>/dev/null | tr '\r' '\n' | grep -F '[DIRTYBIRD]' | tail -n1 | sed $'s/\x1b\\[[0-9;]*[mK]//g')
    if [[ -n $line ]]; then
        khs=$(echo "$line" | grep -oE '[0-9]+(\.[0-9]+)? KH/s' | head -n1 | grep -oE '^[0-9]+(\.[0-9]+)?')
        acc=$(echo "$line" | grep -oE 'Miniblocks:[0-9]+' | head -n1 | grep -oE '[0-9]+')
        rej=$(echo "$line" | grep -oE 'REJ:[0-9]+' | head -n1 | grep -oE '[0-9]+')
        hms=$(echo "$line" | grep -oE '[0-9]+:[0-9]{2}:[0-9]{2}' | tail -n1)
        if [[ -n $hms ]]; then
            h=${hms%%:*}; rest=${hms#*:}; m=${rest%%:*}; s=${rest#*:}
            uptime=$(( 10#$h * 3600 + 10#$m * 60 + 10#$s ))
        fi
    fi
fi

[[ -z $khs ]] && khs=0
[[ -z $acc ]] && acc=0
[[ -z $rej ]] && rej=0
[[ -z $uptime ]] && uptime=0

stats=$(cat <<-END
{
    "hs": [$khs],
    "hs_units": "khs",
    "uptime": $uptime,
    "ar": [$acc, $rej],
    "algo": "ASTROBWT"
}
END
)
