import socket
import struct
import random

DNS_PORT = 53
TIMEOUT_SECONDS = 5

# record types and response codes we know the names of
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

ALLOWED_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-_")

# Building Query

def encode_domain(domain):
    # remove trailing dot if there are
    domain = domain.strip().rstrip(".")

    if domain == "":
        raise ValueError("domain name is empty")
    if len(domain) > 253:
        raise ValueError("domain name is too long")

    encoded = b""
    for label in domain.split("."):
        # each label needs 1 to 63 characters
        if len(label) == 0 or len(label) > 63:
            raise ValueError("invalid label in domain name: '" + label + "'")
        if not set(label.lower()) <= ALLOWED_CHARS:
            raise ValueError("invalid characters in label: '" + label + "'")
        # length byte first, then the label itself
        encoded += bytes([len(label)]) + label.encode("ascii")

    # zero byte marks the end of the name
    return encoded + b"\x00"


def build_query(domain):
    tid = random.randint(0, 65535)

    # create DNS header (12 bytes)
    flags = 0x0100  # only the RD bit is set
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)

    qname = encode_domain(domain)

    # question: name + type A (1) + class IN (1)
    question = qname + struct.pack("!HH", 1, 1)

    return tid, header + question

# Sending Query

def send_query(packet, server_ip):
    # validating server ip
    try:
        socket.inet_pton(socket.AF_INET, server_ip)
    except OSError:
        raise ValueError("'" + server_ip + "' is not a valid IPv4 address")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        # send query
        sock.sendto(packet, (server_ip, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()

# Parsing response

def read_name(data, pos):
    labels = []
    next_pos = None
    jumps = 0

    while True:
        if pos >= len(data):
            raise ValueError("name goes past end of packet")

        length = data[pos]

        if length == 0:
            pos += 1
            break

        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                raise ValueError("bad compression pointer")
            offset = ((length & 0x3F) << 8) | data[pos + 1]
            if next_pos is None:
                next_pos = pos + 2  
            jumps += 1
            if jumps > 20:
                raise ValueError("compression pointer loop")
            pos = offset
            continue

        if (length & 0xC0) != 0:
            raise ValueError("unknown label type")

        pos += 1
        if pos + length > len(data):
            raise ValueError("label goes past end of packet")
        labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length

    if next_pos is None:
        next_pos = pos
    return ".".join(labels), next_pos


def parse_header(data):
    if len(data) < 12:
        raise ValueError("response is shorter than a DNS header")

    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])

    header = {
        "id": tid,
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "aa": (flags >> 10) & 1,
        "tc": (flags >> 9) & 1,
        "rd": (flags >> 8) & 1,
        "ra": (flags >> 7) & 1,
        "rcode": flags & 0xF,
        "qdcount": qd,
        "ancount": an,
        "nscount": ns,
        "arcount": ar,
    }
    return header


def parse_question(data, pos):
    name, pos = read_name(data, pos)
    if pos + 4 > len(data):
        raise ValueError("question section is cut off")
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    return {"name": name, "type": qtype, "class": qclass}, pos + 4


def parse_record(data, pos):
    # parse answer
    name, pos = read_name(data, pos)

    # type(2) class(2) ttl(4) rdlength(2)
    if pos + 10 > len(data):
        raise ValueError("answer record is cut off")
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
    pos += 10

    if pos + rdlen > len(data):
        raise ValueError("record data is cut off")
    rdata = data[pos:pos + rdlen]

    record = {"name": name, "type": rtype, "class": rclass, "ttl": ttl}

    if rtype == 1:
        # A record, must be exactly 4 bytes
        if rdlen != 4:
            raise ValueError("A record has wrong length")
        record["value"] = socket.inet_ntoa(rdata)
    elif rtype == 5 or rtype == 2:
        # CNAME / NS, rdata is a domain name (may use compression)
        record["value"], _ = read_name(data, pos)
    elif rtype == 28 and rdlen == 16:
        record["value"] = socket.inet_ntop(socket.AF_INET6, rdata)
    else:
        record["value"] = rdata.hex()

    return record, pos + rdlen

# Showing result

def show_response(data, expected_id, domain, server_ip):
    header = parse_header(data)

    # check that this is the reply we are waiting for
    if header["id"] != expected_id:
        raise ValueError("transaction ID does not match the query")
    if header["qr"] != 1:
        raise ValueError("packet is not a DNS response")

    status = RCODE_NAMES.get(header["rcode"], "UNKNOWN (" + str(header["rcode"]) + ")")

    print("\n===== DNS RESPONSE =====")
    print("DNS server      :", server_ip + ":" + str(DNS_PORT))
    print("Domain queried  :", domain)
    print("Transaction ID  :", header["id"], "(" + hex(header["id"]) + ")")
    print("Response flag   :", "Yes" if header["qr"] else "No")
    print("Authoritative   :", "Yes" if header["aa"] else "No")
    print("Truncated       :", "Yes" if header["tc"] else "No")
    print("Recursion desired  :", "Yes" if header["rd"] else "No")
    print("Recursion available:", "Yes" if header["ra"] else "No")
    print("Status (RCODE)  :", status)
    print("Questions/Answers/Authority/Additional:",
          header["qdcount"], header["ancount"], header["nscount"], header["arcount"])

    if header["rcode"] == 3:
        print("\nDomain does not exist (NXDOMAIN).")
        return
    if header["rcode"] != 0:
        print("\nServer returned an error:", status)
        return

    # parse question section
    pos = 12
    print("\n===== QUESTION =====")
    for _ in range(header["qdcount"]):
        q, pos = parse_question(data, pos)
        print("Query name  :", q["name"])
        print("Query type  :", q["type"], "(" + TYPE_NAMES.get(q["type"], "?") + ")")
        print("Query class :", q["class"], "(IN)" if q["class"] == 1 else "")

    # parse answers
    print("\n===== ANSWERS =====")
    if header["ancount"] == 0:
        print("No answer records in the response.")
        return

    ipv4_list = []
    for i in range(header["ancount"]):
        rec, pos = parse_record(data, pos)
        type_name = TYPE_NAMES.get(rec["type"], "type " + str(rec["type"]))
        print("\nAnswer", i + 1)
        print("  Name  :", rec["name"])
        print("  Type  :", rec["type"], "(" + type_name + ")")
        print("  Class :", rec["class"])
        print("  TTL   :", rec["ttl"], "seconds")
        if rec["type"] == 1:
            print("  IPv4  :", rec["value"])
            ipv4_list.append(rec["value"])
        else:
            print("  Data  :", rec["value"])

    if ipv4_list:
        print("\nResolved IPv4 address(es):", ", ".join(ipv4_list))
    else:
        print("\nNo A record found in the answers.")

# Main program

def lookup(domain, server_ip):
    try:
        tid, packet = build_query(domain)
        print("\nSending query for", domain, "to", server_ip + ":" + str(DNS_PORT), "...")
        response = send_query(packet, server_ip)

        if response is None:
            print("Request timed out, no reply from the server.")
            return

        show_response(response, tid, domain, server_ip)

    except ValueError as e:
        print("Error:", e)
    except (struct.error, IndexError):
        print("Error: malformed DNS response")
    except OSError as e:
        print("Network error:", e)


def main():
    print("=== DNS Query Program ===")

    # dns server is asked only once
    server_ip = input("Enter DNS server IP (e.g. 8.8.8.8): ").strip()

    while True:
        try:
            domain = input("\nEnter domain name (or 'quit'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if domain.lower() == "quit":
            print("Exiting.")
            break
        if domain == "":
            print("Please type a domain name.")
            continue

        lookup(domain, server_ip)


if __name__ == "__main__":
    main()