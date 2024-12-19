import argparse
import struct
import sys
import socket
import random
import json

A_RECORD = 1
AAAA_RECORD = 28
CNAME_RECORD = 5
NS_RECORD = 2

INTERNET_CLASS = 1

HEADER_STRUCTURE = "!HHHHHH"


def domain_encoder(domain_name):
    domain_name = domain_name.rstrip('.')
    encoded_parts = [struct.pack('B', len(part)) + part.encode() for part in domain_name.split('.')]
    encoded_domain = b''.join(encoded_parts) + b'\x00'

    if any(len(part) > 63 for part in domain_name.split('.')):
        raise ValueError("A segment exceeds 63 characters")
    
    return encoded_domain


def dns_query_constructor(target_name, query_type):
    txn_id = random.randint(0, 65535)
    flags = 0x0100  
    question_count = 1
    answer_count = 0
    ns_count = 0
    additional_count = 0
    header_data = struct.pack(HEADER_STRUCTURE, txn_id, flags, question_count, answer_count, ns_count, additional_count)

    name_encoded = domain_encoder(target_name)
    question = name_encoded + struct.pack('!HH', query_type, INTERNET_CLASS)

    return header_data + question


def generate_request(arguments):
    query_type = A_RECORD if arguments.ipv4 else AAAA_RECORD
    try:
        dns_query = dns_query_constructor(arguments.target, query_type)
    except ValueError as error:
        sys.stderr.write(f"Domain encoding error: {error}\n")
        sys.exit(1)

    query_size = len(dns_query)
    prefixed_query = struct.pack('!H', query_size) + dns_query
    sys.stdout.buffer.write(prefixed_query)


def label_parser(data_stream, start_offset):
    labels, jumps = [], 0
    used_jump, original_offset = False, start_offset

    while jumps <= 5:
        if start_offset >= len(data_stream):
            raise ValueError("Offset exceeds data stream length while parsing labels")
        
        length = data_stream[start_offset]
        if length == 0:
            start_offset += 1
            break

        if length & 0xC0 == 0xC0:
            if not used_jump:
                original_offset = start_offset + 2
                used_jump = True
            start_offset = struct.unpack('!H', data_stream[start_offset:start_offset + 2])[0] & 0x3FFF
            jumps += 1
        else:
            segment_end = start_offset + 1 + length
            if segment_end > len(data_stream):
                raise ValueError("Label segment length exceeds data stream length")
            labels.append(data_stream[start_offset + 1:segment_end].decode())
            start_offset = segment_end

    return '.'.join(labels), (original_offset if used_jump else start_offset)


def parse_dns_response(data):
    try:
        if len(data) < 12:
            return {"kind": "malformed"}

        header = struct.unpack(HEADER_STRUCTURE, data[:12])
        transaction_id, flags, qdcount, ancount, nscount, arcount = header
        qr = (flags >> 15) & 0x1
        rcode = flags & 0xF

        if qr != 1:
            return {"kind": "malformed"}

        if rcode == 3:
            return {"kind": "error", "rcode": 3} 

        if rcode != 0:
            return {"kind": "error", "rcode": rcode}

        offset = 12

        for _ in range(qdcount):
            _, offset = label_parser(data, offset)
            offset += 4 

        addresses, cname_chain, ns_records = [], [], []
        additional_records = {}

        for _ in range(ancount):
            name, offset = label_parser(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            if rtype == A_RECORD and rdlength == 4:
                addr = socket.inet_ntop(socket.AF_INET, rdata)
                addresses.append(addr)
            elif rtype == AAAA_RECORD and rdlength == 16:
                addr = socket.inet_ntop(socket.AF_INET6, rdata)
                addresses.append(addr)
            elif rtype == CNAME_RECORD:
                cname, _ = label_parser(data, offset - rdlength)
                cname_chain.append(cname)

        for _ in range(nscount):
            ns_name, offset = label_parser(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength
            if rtype == NS_RECORD:
                ns_target, _ = label_parser(data, offset - rdlength)
                ns_records.append(ns_target)

        for _ in range(arcount):
            name, offset = label_parser(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            offset += rdlength

            if rtype == A_RECORD and rdlength == 4:
                addr = socket.inet_ntop(socket.AF_INET, rdata)
                if name not in additional_records:
                    additional_records[name] = []
                additional_records[name].append(addr)
            elif rtype == AAAA_RECORD and rdlength == 16:
                addr = socket.inet_ntop(socket.AF_INET6, rdata)
                if name not in additional_records:
                    additional_records[name] = []
                additional_records[name].append(addr)

        if addresses:
            return {"kind": "address", "addresses": list(set(addresses))}
        elif cname_chain:
            return {"kind": "next-name", "next-name": cname_chain[-1]}
        elif ns_records:
            next_server_addresses = []
            for ns in ns_records:
                if ns in additional_records:
                    next_server_addresses.extend(additional_records[ns])
            return {
                "kind": "next-server",
                "next-server-names": ns_records,
                "next-server-addresses": next_server_addresses
            }

        return {"kind": "malformed"}

    except Exception as e:
        return {"kind": "malformed", "error": str(e)}


def handle_response(arguments):
    try:
        size_header = sys.stdin.buffer.read(2)
        if len(size_header) < 2:
            print(json.dumps({"kind": "malformed"}))
            sys.exit(0)
        msg_size = struct.unpack('!H', size_header)[0]
        dns_payload = sys.stdin.buffer.read(msg_size)
        if len(dns_payload) < msg_size:
            print(json.dumps({"kind": "malformed"}))
            sys.exit(0)

        result_data = parse_dns_response(dns_payload)
        print(json.dumps(result_data))
    except Exception as error:
        print(json.dumps({"kind": "malformed", "error": str(error)}))


def transmit_request(arguments):
    query_type = A_RECORD if arguments.ipv4 else AAAA_RECORD
    try:
        dns_query = dns_query_constructor(arguments.target, query_type)
    except ValueError as error:
        sys.stderr.write(f"Domain encoding error: {error}\n")
        sys.exit(1)

    query_length = len(dns_query)
    sendable_query = struct.pack('!H', query_length) + dns_query

    try:
        with socket.create_connection((arguments.server, arguments.port), timeout=5) as connection:
            connection.sendall(sendable_query)
            resp_header = connection.recv(2)
            if len(resp_header) < 2:
                print(json.dumps({"kind": "malformed"}))
                return
            response_size = struct.unpack('!H', resp_header)[0]
            response_data = b''
            while len(response_data) < response_size:
                chunk = connection.recv(response_size - len(response_data))
                if not chunk:
                    break
                response_data += chunk
            if len(response_data) != response_size:
                print(json.dumps({"kind": "malformed"}))
                return
            result = parse_dns_response(response_data)
            print(json.dumps(result))
    except socket.timeout:
        print(json.dumps({"kind": "error", "error": "Connection timed out"}))
    except Exception as error:
        print(json.dumps({"kind": "error", "error": str(error)}))


def main():
    parser = argparse.ArgumentParser(description='Custom DNS Query Tool')
    command_group = parser.add_mutually_exclusive_group(required=True)

    command_group.add_argument('--create-request', nargs=1, metavar='DOMAIN', help='Generate DNS query')
    command_group.add_argument('--process-response', action='store_true', help='Parse DNS response data')
    command_group.add_argument('--send-request', nargs=1, metavar='DOMAIN', help='Transmit DNS query via TCP')

    parser.add_argument('--ipv4', action='store_true', help='Query for IPv4 address')
    parser.add_argument('--ipv6', action='store_true', help='Query for IPv6 address')
    parser.add_argument('--server', type=str, help='DNS server address for sending request')
    parser.add_argument('--port', type=int, help='DNS server port for sending request')

    args = parser.parse_args()

    if args.create_request:
        if not (args.ipv4 ^ args.ipv6):
            sys.stderr.write("Specify --ipv4 or --ipv6 with --create-request\n")
            sys.exit(1)
        args.target = args.create_request[0]
        generate_request(args)
    elif args.process_response:
        handle_response(args)
    elif args.send_request:
        if not (args.ipv4 ^ args.ipv6):
            sys.stderr.write("Specify --ipv4 or --ipv6 with --send-request\n")
            sys.exit(1)
        if not args.server or not args.port:
            sys.stderr.write("Both --server and --port required with --send-request\n")
            sys.exit(1)
        args.target = args.send_request[0]
        transmit_request(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
