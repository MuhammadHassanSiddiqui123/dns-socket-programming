# DNS Query Resolution using Socket Programming

**Course:** [Course Name / Code]
**Student:** [Your Full Name] — Roll No: 24K-1051
**Assignment:** Section (A) — DNS Query Resolution using Socket Programming

## Overview

This project implements a DNS client from scratch using raw **UDP sockets**.
It builds a DNS query message by hand (Header + Question section per
RFC 1035), sends it to a user-specified DNS server on port 53, and manually
parses the raw response (Header, Question, and Answer sections) to display
the resolved IPv4 address, TTL, and other relevant fields.

**No high-level resolver functions** (e.g. `socket.gethostbyname()`,
`socket.getaddrinfo()`) are used to perform the actual resolution — the DNS
protocol is implemented directly on top of `socket.SOCK_DGRAM`.

## Features

- Constructs the 12-byte DNS header and Question section manually
  (Transaction ID, RD flag, QDCOUNT, QTYPE=A, QCLASS=IN)
- Parses the response header, including QR/AA/TC/RD/RA flags and RCODE
- Decodes domain names in the response, including DNS **name compression**
  pointers (RFC 1035 §4.1.4)
- Parses Answer records: NAME, TYPE, TTL, RDLENGTH, RDATA
- Resolves and displays IPv4 addresses for A records
- Follows CNAME chains (alias → final A record)
- Handles NXDOMAIN, SERVFAIL, and other error RCODEs without crashing
- Handles request timeouts and malformed/truncated responses gracefully
- Validates domain name syntax and DNS server IP before sending
- Supports multiple lookups in a single run (loop until `quit`/`exit`)
- DNS server IP is supplied at runtime; standard port 53 is always used

## Files

| File | Description |
|---|---|
| `dns_client.py` | Main program — run this file |
| `README.md` | This file |
| `screenshots/` | Test run screenshots (see below) |

## Requirements

- Python 3.x (no external libraries — uses only the standard library:
  `socket`, `struct`, `random`, `sys`)

## How to Run

```bash
python3 dns_client.py
```

You will be prompted for:
1. A DNS server IP address (e.g. `8.8.8.8` for Google Public DNS, or
   `1.1.1.1` for Cloudflare)
2. A domain name to look up (repeat as many times as needed)
3. Type `quit` or `exit` to stop

## Example Session

```
============================================================
 Simple DNS Query Tool (raw UDP sockets, RFC 1035)
============================================================
Enter the DNS server IP address to query (e.g. 8.8.8.8): 8.8.8.8

Using DNS server 8.8.8.8 on port 53 for this session.
Type a domain name to look it up, or 'quit'/'exit' to stop.

Domain name: www.example.com

----- DNS Response -----
Transaction ID (sent) : 64814
Transaction ID (recv) : 64814
Query name             : www.example.com
Query type              : A (IPv4 address)
Response code (RCODE)   : 0 -> NOERROR - No error condition
Flags                   : QR=1 AA=0 TC=0 RD=1 RA=1
Answer count            : 2

  Answer record #1
    Name  : www.example.com
    Type  : A
    TTL   : 300 seconds
    IPv4 address : 104.20.23.154

  Answer record #2
    Name  : www.example.com
    Type  : A
    TTL   : 300 seconds
    IPv4 address : 172.66.147.243

Domain name: quit
Goodbye.
```

## Test Cases Demonstrated

| # | Domain | Purpose |
|---|---|---|
| 1 | `www.example.com` | Common `.com` domain, multiple A records |
| 2 | `www.wikipedia.org` | `.org` domain, demonstrates CNAME-chain resolution |
| 3 | `thisdomaindoesnotexist9999zzz.com` | Invalid domain → NXDOMAIN handled gracefully |

Screenshots of each run are included in `screenshots/`.

## Design Notes

- **Header:** ID, flags (QR, Opcode, AA, TC, RD, RA, RCODE), QDCOUNT,
  ANCOUNT, NSCOUNT, ARCOUNT — parsed with `struct.unpack("!HHHHHH", ...)`.
- **Question section:** domain name encoded as length-prefixed labels
  terminated by a zero byte, followed by QTYPE and QCLASS.
- **Answer section:** each record's NAME may be a compressed pointer
  (top two bits `11`) into an earlier part of the message; `decode_name()`
  follows these pointers correctly per RFC 1035.
- **Error handling:** `socket.timeout` for no response, RCODE checks for
  NXDOMAIN/SERVFAIL/etc., and `try/except` around parsing to catch
  truncated or malformed packets.

## References

- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [Python `socket` module documentation](https://docs.python.org/3/library/socket.html)
