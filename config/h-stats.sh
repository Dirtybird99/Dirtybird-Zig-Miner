#!/usr/bin/env bash
. /hive/miners/custom/zig-miner/h-manifest.conf

# zig-miner has no HTTP stats API; it prints a live status line to the log via
# carriage-return (\r) updates in the form:
#   HHH:MM:SS H:<height> IB:<n> MB:<accepted> MBR:<rejected> SH:<n> Diff:<n> @ <X.XX> KH/s (<Y.YY> avg)
# We read the tail of the log, turn the \r-overwritten line into newlines, and
# scrape the freshest values for the HiveOS dashboard.

LOG="${CUSTOM_LOG_BASENAME}.log"

khs=0
uptime=0
acc=0
rej=0

if [[ -f $LOG ]]; then
    line=$(tail -c 8192 "$LOG" 2>/dev/null | tr '\r' '\n' | grep 'KH/s' | tail -n1)
    if [[ -n $line ]]; then
        # hashrate: the only token followed by "KH/s" (the avg field has no unit)
        khs=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+ KH/s' | tail -n1 | grep -oE '[0-9]+\.[0-9]+')
        # MB: = accepted shares, MBR: = rejected shares (MB: won't match MBR's MB)
        acc=$(echo "$line" | grep -oE 'MB:[0-9]+' | grep -oE '[0-9]+')
        rej=$(echo "$line" | grep -oE 'MBR:[0-9]+' | grep -oE '[0-9]+')
        # leading HHH:MM:SS elapsed -> uptime in seconds
        hms=$(echo "$line" | grep -oE '^[0-9]{3}:[0-9]{2}:[0-9]{2}')
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
