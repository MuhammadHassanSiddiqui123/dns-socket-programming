#!/usr/bin/env python3
"""
dns_client.py
=============

A minimal DNS query/response tool built directly on top of UDP sockets.

This program constructs raw DNS query messages (Header + Question section)
by hand, sends them to a user-specified DNS server on the standard DNS
port (53), receives the raw response, and manually parses the Header,
Question, and Answer sections according to RFC 1035.

It deliberately does NOT use any high-level resolver call such as
socket.gethostbyname() or socket.getaddrinfo() for the actual resolution --
those are used nowhere in this file except to validate the DNS server IP
the user types in (an address, not a hostname).

Usage:
    python3 dns_client.py

Then follow the prompts:
    1. Enter the DNS server IP address once (used for the whole session).
    2. Enter domain names one at a time; type 'quit' or 'exit' to stop.

Author: (your name)
"""

import socket
import struct
import random
import sys

DNS_PORT = 53
TIMEOUT_SECONDS = 4  # how long to wait for a response before giving up
QUERY_TYPE_A = 1     # A record (IPv4 address)
QUERY_CLASS_IN = 1   # Internet class

# RFC 1035 section 4.1.1 -- RCODE meanings we care about
RCODE_MEANINGS = {
    0: "NOERROR - No error condition",
    1: "FORMERR - The name server was unable to interpret the query",
    2: "SERVFAIL - The name server was unable to process this query",
    3: "NXDOMAIN - The domain name referenced in the query does not exist",
    4: "NOTIMP - The name server does not support the requested kind of query",
    5: "REFUSED - The name server refuses to perform the operation",
}

# Minimal map of RR TYPE numbers to names, for display purposes only.
RR_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
}


# ---------------------------------------------------------------------------
# Domain-name validation
# ---------------------------------------------------------------------------
def is_valid_domain(domain):
    """
    Perform a basic sanity check on a user-supplied domain name.

    This is NOT a full RFC 1035/1123 validator, just enough to reject
    obviously malformed input (empty string, spaces, no dot, illegal
    characters, labels that are too long) before we try to encode it.
    """
    if not domain or len(domain) > 253:
        return False
    if " " in domain or "\t" in domain:
        return False
    if "." not in domain:
        return False

    labels = domain.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


# ---------------------------------------------------------------------------
# Query construction
# ---------------------------------------------------------------------------
def encode_domain_name(domain):
    """
    Encode a domain name into DNS "labels" wire format.

    Example: "www.example.com" ->
        b'\x03www\x07example\x03com\x00'

    Each label is preceded by a single length byte, and the whole
    sequence is terminated with a zero-length byte (the root label).
    """
    encoded = b""
    for label in domain.split("."):
        label_bytes = label.encode("ascii")
        encoded += struct.pack("B", len(label_bytes)) + label_bytes
    encoded += b"\x00"  # terminating root label
    return encoded


def build_dns_query(domain, transaction_id, qtype=QUERY_TYPE_A):
    """
    Build a complete DNS query message: Header + Question section.

    Header layout (12 bytes, RFC 1035 4.1.1):
        ID (16 bits)
        Flags (16 bits)
        QDCOUNT (16 bits)
        ANCOUNT (16 bits)
        NSCOUNT (16 bits)
        ARCOUNT (16 bits)

    Flags we set:
        QR = 0   (this is a query)
        Opcode = 0 (standard query)
        RD = 1   (recursion desired -- ask the server to chase the
                   hierarchy - root/TLD/authoritative - on our behalf)
    """
    # QR(1) Opcode(4) AA(1) TC(1) RD(1) | RA(1) Z(3) RCODE(4)
    flags = 0
    flags |= (0 << 15)  # QR = 0 -> query
    flags |= (0 << 11)  # Opcode = 0 -> standard query
    flags |= (0 << 10)  # AA = 0 (meaningless in a query)
    flags |= (0 << 9)   # TC = 0
    flags |= (1 << 8)   # RD = 1 -> recursion desired

    header = struct.pack(
        "!HHHHHH",
        transaction_id,  # ID
        flags,           # Flags
        1,               # QDCOUNT = 1 question
        0,               # ANCOUNT
        0,               # NSCOUNT
        0,               # ARCOUNT
    )

    question = encode_domain_name(domain)
    question += struct.pack("!HH", qtype, QUERY_CLASS_IN)  # QTYPE, QCLASS

    return header + question


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def decode_name(data, offset):
    """
    Decode a (possibly compressed) domain name starting at `offset`
    within the full response `data`.

    DNS uses a compression scheme (RFC 1035 4.1.4) where a name can end
    with a pointer (top two bits of the length byte set to 11) instead
    of a zero-length terminator, pointing back to an earlier occurrence
    of the same name in the message. We must follow such pointers.

    Returns (name_string, next_offset) where next_offset is the offset
    in `data` immediately after this name's encoding (before following
    any pointer -- i.e. the correct position to keep parsing the record).
    """
    labels = []
    pos = offset
    jumped = False
    original_next_offset = None

    while True:
        length_byte = data[pos]

        # Pointer: two highest bits are 11 (0xC0)
        if (length_byte & 0xC0) == 0xC0:
            if not jumped:
                # Remember where to resume normal parsing after this name
                original_next_offset = pos + 2
            pointer = struct.unpack("!H", data[pos:pos + 2])[0]
            pos = pointer & 0x3FFF  # lower 14 bits = offset from start of message
            jumped = True
            continue

        if length_byte == 0:
            pos += 1
            if not jumped:
                original_next_offset = pos
            break

        pos += 1
        label = data[pos:pos + length_byte].decode("ascii", errors="replace")
        labels.append(label)
        pos += length_byte

    name = ".".join(labels)
    return name, original_next_offset


def parse_header(data):
    """Parse the 12-byte DNS header and return a dict of its fields."""
    (transaction_id, flags, qdcount, ancount,
     nscount, arcount) = struct.unpack("!HHHHHH", data[:12])

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF

    return {
        "transaction_id": transaction_id,
        "qr": qr,
        "opcode": opcode,
        "aa": aa,
        "tc": tc,
        "rd": rd,
        "ra": ra,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


def parse_question(data, offset):
    """Parse a single Question section entry. Returns (dict, next_offset)."""
    name, offset = decode_name(data, offset)
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    offset += 4
    return {"name": name, "qtype": qtype, "qclass": qclass}, offset


def parse_resource_record(data, offset):
    """
    Parse a single Resource Record (used for Answer/Authority/Additional
    sections). Returns (record_dict, next_offset).

    RR layout (RFC 1035 4.1.3):
        NAME     (variable, possibly compressed)
        TYPE     (16 bits)
        CLASS    (16 bits)
        TTL      (32 bits)
        RDLENGTH (16 bits)
        RDATA    (RDLENGTH bytes)
    """
    name, offset = decode_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    rdata_raw = data[offset:offset + rdlength]

    record = {
        "name": name,
        "type": rtype,
        "type_name": RR_TYPE_NAMES.get(rtype, str(rtype)),
        "class": rclass,
        "ttl": ttl,
        "rdlength": rdlength,
    }

    if rtype == QUERY_TYPE_A and rdlength == 4:
        record["address"] = ".".join(str(b) for b in rdata_raw)
    elif rtype == 5:  # CNAME
        cname, _ = decode_name(data, offset)
        record["cname"] = cname
    else:
        record["address"] = None

    offset += rdlength
    return record, offset


def parse_dns_response(data):
    """
    Fully parse a raw DNS response message into a structured dict:
        {
            "header": {...},
            "questions": [...],
            "answers": [...],
        }

    Raises ValueError if the message is too short / malformed.
    """
    if len(data) < 12:
        raise ValueError("Response too short to contain a valid DNS header")

    header = parse_header(data)
    offset = 12

    questions = []
    for _ in range(header["qdcount"]):
        q, offset = parse_question(data, offset)
        questions.append(q)

    answers = []
    for _ in range(header["ancount"]):
        rr, offset = parse_resource_record(data, offset)
        answers.append(rr)

    return {"header": header, "questions": questions, "answers": answers}


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
def send_dns_query(server_ip, domain, qtype=QUERY_TYPE_A, timeout=TIMEOUT_SECONDS):
    """
    Send a DNS query for `domain` to `server_ip` on UDP port 53 and
    return (transaction_id, raw_response_bytes).

    Raises socket.timeout if no response arrives in time, and OSError
    for other socket-level failures (e.g. unreachable host).
    """
    transaction_id = random.randint(0, 0xFFFF)
    query = build_dns_query(domain, transaction_id, qtype)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server_ip, DNS_PORT))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    return transaction_id, response


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
def print_result(sent_id, domain, qtype, parsed):
    """Pretty-print the parsed DNS response for the user."""
    header = parsed["header"]

    print("\n----- DNS Response -----")
    print(f"Transaction ID (sent) : {sent_id}")
    print(f"Transaction ID (recv) : {header['transaction_id']}")
    if header["transaction_id"] != sent_id:
        print("  WARNING: Transaction ID mismatch -- response may not "
              "correspond to this query (spoofed or delayed packet).")

    print(f"Query name             : {domain}")
    print(f"Query type              : A (IPv4 address)" if qtype == QUERY_TYPE_A
          else f"Query type              : {qtype}")

    rcode = header["rcode"]
    print(f"Response code (RCODE)   : {rcode} -> "
          f"{RCODE_MEANINGS.get(rcode, 'Unknown RCODE')}")
    print(f"Flags                   : QR={header['qr']} AA={header['aa']} "
          f"TC={header['tc']} RD={header['rd']} RA={header['ra']}")
    print(f"Answer count            : {header['ancount']}")

    if rcode != 0:
        print("No usable answer -- the server reported an error for this query.")
        return

    if not parsed["answers"]:
        print("Server returned NOERROR but no answer records were included.")
        return

    for i, rr in enumerate(parsed["answers"], start=1):
        print(f"\n  Answer record #{i}")
        print(f"    Name  : {rr['name']}")
        print(f"    Type  : {rr['type_name']}")
        print(f"    TTL   : {rr['ttl']} seconds")
        if rr["type_name"] == "A":
            print(f"    IPv4 address : {rr.get('address')}")
        elif rr["type_name"] == "CNAME":
            print(f"    Canonical name (alias target) : {rr.get('cname')}")
        else:
            print(f"    (RDATA of {rr['rdlength']} bytes not decoded for this type)")


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------
def get_dns_server_ip():
    """Prompt the user for a DNS server IP address, with basic validation."""
    while True:
        server_ip = input("Enter the DNS server IP address to query "
                           "(e.g. 8.8.8.8): ").strip()
        try:
            socket.inet_aton(server_ip)  # validates dotted-quad IPv4 syntax
            return server_ip
        except OSError:
            print("That doesn't look like a valid IPv4 address. Try again.\n")


def main():
    print("=" * 60)
    print(" Simple DNS Query Tool (raw UDP sockets, RFC 1035)")
    print("=" * 60)

    server_ip = get_dns_server_ip()
    print(f"\nUsing DNS server {server_ip} on port {DNS_PORT} for this session.")
    print("Type a domain name to look it up, or 'quit'/'exit' to stop.\n")

    while True:
        domain = input("Domain name: ").strip()

        if domain.lower() in ("quit", "exit"):
            print("Goodbye.")
            break

        if not domain:
            print("Please enter a non-empty domain name.\n")
            continue

        if not is_valid_domain(domain):
            print(f"'{domain}' does not look like a valid domain name. "
                  "Please try again.\n")
            continue

        try:
            sent_id, raw_response = send_dns_query(server_ip, domain)
        except socket.timeout:
            print(f"Request timed out: no response from {server_ip} "
                  f"within {TIMEOUT_SECONDS} seconds.\n")
            continue
        except OSError as e:
            print(f"Network error while contacting {server_ip}: {e}\n")
            continue

        try:
            parsed = parse_dns_response(raw_response)
        except (ValueError, struct.error, IndexError) as e:
            print(f"Received a malformed or unparseable response: {e}\n")
            continue

        print_result(sent_id, domain, QUERY_TYPE_A, parsed)
        print()  # blank line before next prompt


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)