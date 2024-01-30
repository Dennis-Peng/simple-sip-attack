# sip-attack

## Quikstart

1. Start redis
```sh
sudo apt install redis
sudo systemctl enable --now redis-server
```

2. Replay pcap file on dummy1 interface.

```sh
tcpreplay -i dummy1 --pps 100  --loop 1 -K build/ip_lo_relation2.pcap+m.pcap
```

3. Run `netflow_filter.py` to sniffing net flow.

```sh
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "$(readlink -f `which python3`)"
python3 netflow_filter.py -i dummy1
```
