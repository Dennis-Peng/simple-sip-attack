import re
import threading
import hashlib
import time
from queue import SimpleQueue, Empty
from typing import Mapping, Callable
from collections import Counter
import json


from cachetools import TTLCache
from redis import Redis
from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import TCP, UDP, IP

from sip_analyze import is_sip, unpack_sip, validate_sip


def redis_hash(d: Mapping):
    h = {}
    for k, v in d.items():
        if v is None:
            v = ''

        if isinstance(v, bool):
            v = 'true' if v else 'false'
        elif isinstance(v, (int, float, bytes, str)):
            pass
        else:
            v = str(v)
        h[k] = v
    return h


class NetFlowError(ValueError):
    pass


def connect_redis(url):
    """Connect redis server with url, such as `username:password@127.0.0.1:6379`"""
    pattern = r'(?:(?P<name>[^:@]+):(?P<pwd>[^:@]+)@)?(?P<ip>\d+\.\d+\.\d+\.\d+)(?::?(?P<port>\d+))?'
    m = re.match(pattern, url)
    if m is None:
        raise ValueError('Invalid redis url')
    r = Redis(
        host=m.group('ip'),
        port=m.group('port'),
        username=m.group('name'),
        password=m.group('pwd'),
    )
    return r


def _update_sip_sess_cache(
    packet: Packet,
    payloads: dict,
    sess_cache: TTLCache,
):
    """Update SIP Session cache."""
    callid = payloads['callid']
    if callid not in sess_cache:
        sess_cache[callid] = {
            'callid': callid,
            'begin': packet.time,
            'end': None,
            'num_packets': 1,
            'num_malformed': 0,
            'num_replay': 0,
            'from': payloads.get('from'),
            'to': payloads.get('to'),
            'src': payloads.get('src'),
            'dst': payloads.get('dst'),
            'duration': 0,
        }
    else:
        callsess: dict = sess_cache[callid]
        if payloads.get('type', '') == 'BYE':
            callsess['end'] = packet.time
            callsess['duration'] = packet.time - callsess['begin']

        updated_fields = [
            'ad_area_province',
            'ad_area_code',
        ]  # Patch area and other info
        for k in updated_fields:
            v = payloads.get(k)
            if v and v != callsess.get(k):
                callsess[k] = v
        if payloads['malformed']:
            callsess['num_malformed'] += 1
        if payloads['replay'] > 1:
            callsess['num_replay'] += 1

        callsess['num_packets'] += 1
        sess_cache[callid] = callsess


def analyze_sip_packet(
    packet: Packet,
    sess_cache: TTLCache,
    packet_cache: TTLCache,
    last_payloads: Mapping = None,
):
    """Analyze SIP Packet."""
    raw: bytes = packet[Raw].load
    content: str = raw.decode('utf-8', errors='ignore')

    if not is_sip(content):
        return None

    payloads_digest = hashlib.sha256(raw).hexdigest()
    payloads = unpack_sip(content)
    if last_payloads:
        payloads.update(last_payloads)
    ok = validate_sip(payloads)

    if payloads_digest in packet_cache:
        packet_cache[payloads_digest] += 1
    else:
        packet_cache[payloads_digest] = 1

    payloads.update(
        {
            'sha256': payloads_digest,
            'malformed': not ok,
            'replay': packet_cache[payloads_digest],
        }
    )

    _update_sip_sess_cache(packet, payloads, sess_cache)

    return payloads


def analyze_packet(
    packet: Packet, stat_counter: Counter, sess_cache: TTLCache, packet_cache: TTLCache
):
    if IP not in packet:
        return None
    packet_size = len(packet)
    src, dst = packet[IP].src, packet[IP].dst
    tcp_or_udp = None
    if UDP in packet:
        stat_counter['udp_packet'] += 1
        tcp_or_udp = UDP
        stat_counter['udp_traffic'] += packet_size
    elif TCP in packet:
        stat_counter['tcp_packet'] += 1
        stat_counter['tcp_traffic'] += packet_size
        tcp_or_udp = TCP
    else:
        return None

    sport, dport = packet[tcp_or_udp].sport, packet[tcp_or_udp].dport

    _payloads = {
        'src': src,
        'dst': dst,
        'sport': sport,
        'dport': dport,
    }

    if Raw in packet:
        payloads = analyze_sip_packet(
            packet,
            sess_cache=sess_cache,
            packet_cache=packet_cache,
            last_payloads=_payloads,
        )
        if payloads is not None:
            stat_counter['sip_packet'] += 1
            stat_counter['sip_traffic'] += packet_size
            return payloads
    return None


class TaskThread:
    def __init__(self, *args, **kwargs) -> None:
        self._try_stop = False
        self.task_args = args
        self.task_kwargs = kwargs

    def _run(self, *args, **kwargs):
        raise NotImplementedError

    def _setup_thread(self):
        self.thread = threading.Thread(
            target=self._run, args=self.task_args, kwargs=self.task_kwargs
        )
        self.thread.daemon = True

    def is_alive(self):
        return self.thread.is_alive()

    @property
    def running(self):
        return self.thread.is_alive()

    def start(self):
        self._setup_thread()
        self.thread.start()

    def stop(self):
        self._try_stop = True

    def join(self, timeout: float = None):
        self.thread.join(timeout)


class NetFlowHandler(TaskThread):
    """Rebuild sip session and validate sip packet"""

    def __init__(
        self,
        pcap_queue: SimpleQueue,
        sess_cache_size: int = 100000,
        sess_cache_ttl: int = 3600,
        packet_cache_size: int = 1000000,
        packet_cache_ttl: int = 5,
        **kwargs
    ) -> None:
        self.pcap_queue = pcap_queue
        self.sess_cache = TTLCache(maxsize=sess_cache_size, ttl=sess_cache_ttl)
        self.packet_cache = TTLCache(maxsize=packet_cache_size, ttl=packet_cache_ttl)
        self.stat_counter = Counter(
            {
                'packet': 0,  # num of packets
                'udp_packet': 0,
                'tcp_packet': 0,
                'sip_packet': 0,
                'traffic': 0,  # net traffic size
                'udp_traffic': 0,
                'tcp_traffic': 0,
                'sip_traffic': 0,
            }
        )

        super().__init__(
            self.pcap_queue,
            self.stat_counter,
            self.sess_cache,
            self.packet_cache,
            **kwargs
        )

    def _run(
        self,
        pcap_queue: SimpleQueue,
        stat_counter: Counter,
        sess_cache: Mapping,
        packet_cache: Mapping,
        *args,
        **kwargs
    ):
        while not self._try_stop:
            try:
                packet: Packet = pcap_queue.get(timeout=2)
            except Empty:
                continue

            # print(packet, stat_counter)

            stat_counter['packet'] += 1
            stat_counter['traffic'] += len(packet)
            try:
                payloads = analyze_packet(
                    packet,
                    stat_counter=stat_counter,
                    sess_cache=sess_cache,
                    packet_cache=packet_cache,
                )
                if payloads is not None and 'redis' in kwargs:
                    payloads = redis_hash(payloads)
                    kwargs['redis'].xadd('sip_packet_stream', payloads)
            except NetFlowError:
                pass


class AttackDetector(TaskThread):
    """Detect SIP attacks based on history."""

    def __init__(self, *args, det_params: dict = None, **kwargs) -> None:
        if det_params is None:
            det_params = {'replay_ratio': 0.4, 'replay_count': 4}
        super().__init__(det_params, *args, **kwargs)

    def _run(
        self,
        det_params: dict,
        stat_counter: Counter,
        *args,
        sess_cache: TTLCache,
        stat_interval: int = 5,
        **kwargs
    ):
        r: Redis = kwargs.get('redis')
        while not self._try_stop:
            time.sleep(stat_interval)

            for k, v in sess_cache.items():
                if r is not None and v['end']:
                    r.xadd('sip_session_stream', redis_hash(v))

                # Calculate Lv1 attack
                attack_type = None
                if v['num_malformed']:
                    attack_type = 'malformed'
                elif (
                    v['num_replay'] > det_params['replay_ratio'] * v['num_packets']
                    and v['num_replay'] > det_params['replay_count']
                ):
                    attack_type = 'replay'

                if attack_type:
                    v_new = {_k: _v for _k, _v in v.items()}
                    v_new['attack_type'] = attack_type
                    if r is not None:
                        r.xadd('sip_attack_stream', redis_hash(v_new))
                    else:
                        print(v_new)

            # TODO: calculate dos attack based on session history

            # Push stat info
            if r is not None:
                r.xadd('flow_count_stream', stat_counter)
            for k in stat_counter:
                stat_counter[k] = 0
        return


def netflow_filter(iface: str, redis_url: str = None, stat_interval: int = 5):
    pcapfile = None
    if iface.endswith('.pcap'):
        pcapfile = iface
        iface = None

    pcap_queue = SimpleQueue()

    redis = None
    if redis_url:
        redis = connect_redis(redis_url)

    sniffer = AsyncSniffer(
        store=False,
        offline=pcapfile,
        prn=lambda x: pcap_queue.put_nowait(x),
        iface=iface,
    )
    flowhandler = NetFlowHandler(pcap_queue, redis=redis)
    atkdetector = AttackDetector(
        stat_interval=stat_interval,
        stat_counter=flowhandler.stat_counter,
        sess_cache=flowhandler.sess_cache,
        redis=redis,
    )

    sniffer.start()
    flowhandler.start()
    atkdetector.start()

    threads = [sniffer, flowhandler, atkdetector]
    wait = True
    while wait:
        for t in threads:
            if not t.running:
                wait = False
                break
        time.sleep(2)


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-i', '--iface', default='enp9s0')
    parser.add_argument('-r', '--redis', default='127.0.0.1:6379')
    parser.add_argument('-s', '--stat-interval', default=5, type=int)
    args = parser.parse_args()

    print(args)

    netflow_filter(args.iface, redis_url=args.redis, stat_interval=args.stat_interval)
