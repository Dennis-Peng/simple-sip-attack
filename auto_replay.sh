#!/bin/bash

set -e

IFACE=veth0
OFACE=veth1
BACKGROUND_PCAP='background.pcap'
BACKGROUND_REPLAY_SPEED=100
ATTACK_REPLAY_INTERVAL=15
ATTACK_REPLAY_DURATION=20
ATTACK_REPLAY_LOOP=1
ATTACK_REPLAY_SPEED=10
ATTACK_REPLAY_BULK=true
ATTACK_PCAPS=()
DUMP_SNAPLEN=0
DUMP_PCAP=./build/dump_output_$(date +'%Y%m%d%H%M%S').pcap


function showhelp() {
    echo "Replay attack traffic sequentially

Usage: $0 -i NET [-o NET]] [--bulk yes|no] -b BACKGROUND_PCAP [ATTACK_PCAP ...]

Note:
    1. Non-root users need to set network permissions through setcap before using tcpreplay & tcpdump

    $ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpreplay
    $ sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump

    2. Use virtual ethernet interface for tcpreplay & tcpdump

    $ sudo ip link add veth0 type veth peer name veth1
    $ sudo ip link set veth0 up
    $ sudo ip link set veth1 up
    $ sudo ip link set veth0 mtu 9126
    $ sudo ip link set veth1 mtu 9126
"
}

function main() {
    while [ "$#" -gt 0 ]; do
        case $1 in
            -h|--help)
                showhelp
                exit
                ;;
            -b|--background)
                shift
                BACKGROUND_PCAP=$1
                ;;
            --bulk)
                shift
                if [ "$1" == "yes" ]; then
                    ATTACK_REPLAY_BULK=true
                else
                    ATTACK_REPLAY_BULK=false
                fi
                ;;
            -i|--iface)
                shift
                IFACE=$1
                ;;
            -o|--oface)
                shift
                OFACE=$1
                ;;
            -w|--output)
                shift
                DUMP_PCAP=${1// /}
                ;;
            --loop)
                shift
                ATTACK_REPLAY_LOOP=$1
                ;;
            *)
                echo "pos $1"
                ATTACK_PCAPS=("${ATTACK_PCAPS[@]}" "$1")
                ;;
        esac
        shift
    done

    echo $IFACE

    echo ">>> Replaying background pcap $BACKGROUND_PCAP"
    tcpreplay -i $IFACE --pps $BACKGROUND_REPLAY_SPEED -K $BACKGROUND_PCAP &
    BG_REPLAY_PID=$!

    BG_DUMP_PID=
    if [ -n "$DUMP_PCAP" ]; then
        echo ">>> Dumping $DUMP_PCAP"
        mkdir -p "${DUMP_PCAP%/*}/"
        if [[ `tcpdump --version | sed -rn 's/tcpdump version\s+([0-9.]+)/\1/p'` > "4.99" ]]; then
            tcpdump -i $OFACE -s $DUMP_SNAPLEN -w ${DUMP_PCAP} -v --print > "${DUMP_PCAP}.log" &
        else
            echo ">> Unsupported tcpdump version"
            tcpdump -i $OFACE -s $DUMP_SNAPLEN -w - -U | tee ${DUMP_PCAP} | tcpdump -v -r - > "${DUMP_PCAP}.log" &
        fi
        BG_DUMP_PID=$!
    fi

    if $ATTACK_REPLAY_BULK; then
        echo ">>> Bulk-replay is enabled!"
    fi

    for (( i=0; i<$ATTACK_REPLAY_LOOP; ++i )); do
        echo ">>> Loop $i <<<"
        bulk_pids=()
        for pcapfile in "${ATTACK_PCAPS[@]}"; do
            echo ">>> Replaying attack pcap: $pcapfile"
            if $ATTACK_REPLAY_BULK; then
                tcpreplay -i $IFACE --pps $ATTACK_REPLAY_SPEED --duration $ATTACK_REPLAY_DURATION --loop 1 -K $pcapfile &
                bulk_pids=("${bulk_pids[@]}" $!)
            else
                tcpreplay -i $IFACE --pps $ATTACK_REPLAY_SPEED --duration $ATTACK_REPLAY_DURATION --loop 1 -K $pcapfile
                sleep $ATTACK_REPLAY_INTERVAL
            fi
        done
        if [ ${#bulk_pids[@]} -gt 0 ]; then
            wait ${bulk_pids[@]}
            sleep $ATTACK_REPLAY_INTERVAL
        fi
    done
    
    echo ">>> All attack pcaps have been replayed!"

    echo ">>> Wait $ATTACK_REPLAY_INTERVAL seconds to exit..."
    sleep $ATTACK_REPLAY_INTERVAL
    kill $BG_REPLAY_PID
    if [ -n $BG_DUMP_PID ]; then
        kill $BG_DUMP_PID
    fi
}

main "$@"