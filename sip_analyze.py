import re

from scapy.packet import Packet, Raw
from scapy.sendrecv import AsyncSniffer
from scapy.layers.inet import TCP, UDP, IP


def rf(pattern, content, flags=0, fn=None):
    m = re.search(pattern, content, flags=flags)
    if m is None:
        return None
    if fn is None:
        return m.group(0)
    return fn(m)


def is_sip(raw: str):
    return rf(r'^(?:INVITE|ACK|BYE|SIP/2.0)', raw) is not None


def unpack_sip(raw: str):
    """Unpack sip payloads (string)"""
    payloads = {}
    payloads['callid'] = rf(
        r'^Call-ID:\s*([^@]+@.+)', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    payloads['from'] = rf(
        r'^From:\s*<sip:([^@]+)@.*?>', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    payloads['to'] = rf(
        r'^To:\s*<sip:([^@]+)@.*?>', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    payloads['type'] = rf(
        r'^(INVITE|ACK|BYE).*', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    if not payloads['type']:
        payloads['type'] = rf(
            r'^SIP/2.0\s+\d+\s+(.*)', raw, flags=re.M, fn=lambda x: x.group(1)
        )

    payloads['Content-Length'] = rf(
        r'^Content-Length:\s+(\w+)', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    payloads['CSeq'] = rf(r'^CSeq:\s+(\w+)', raw, flags=re.M, fn=lambda x: x.group(1))

    payloads['ad_area_code'] = rf(
        r'^ad_area_code:\s+(\d+)', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    payloads['ad_area_province'] = rf(
        r'^ad_area_province:\s+(\w+)', raw, flags=re.M, fn=lambda x: x.group(1)
    )
    return payloads


def validate_sip(payloads: dict):
    required_keys = ['callid', 'from', 'to', 'type', 'Content-Length', 'CSeq']

    # check necessary header
    for key in required_keys:
        if key not in payloads or not payloads[key]:
            return False # missing mandatory header
    
    # check header format
    sip_uri_pattern = r'^sip:([^@]+)@([^\s>]+)$'
    if not re.match(sip_uri_pattern, payloads['from']):
        return False # malformed from URI
    if not re.match(sip_uri_pattern, payloads['to']):
        return False # malformed to URI
    if not payloads['Content-Length'].isdigit():
        return False # bad Content-Length format
    if not re.match(r'^\d+\s+\w+', payloads['CSeq']):
        return False # bad CSeq format
    
    # FIXME check unfinished line / malformed header field in raw string
    # FIXME check if there exists a blank line at the end of header / between the header and the payload

    return True
