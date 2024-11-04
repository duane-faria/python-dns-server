import struct


def convert_domain_name(domain: str):
    domain_parts = domain.split('.')
    labels = b''

    for part in domain_parts:
        if len(part) == 0:
            continue
        labels += len(part).to_bytes(1, 'big') + part.encode('utf-8')
    labels += b'\x00'

    return labels


# def decode_dns(packet: bytes):
#     decoded_packet: dict = {}
#     header_length = 12
#     question_start_index = header_length + 1
#     headers = struct.unpack('!HHHHHH', packet[:header_length])
#
#     header_id, flags, qd_count, an_count, ns_count, ar_count = headers
#
#     offset = question_start_index+packet[header_length]
#     question_site_name = packet[question_start_index:offset].decode('utf-8')
#     question_site_domain = f"{packet[offset+1:offset + 1 + packet[offset]].decode('utf-8')}"
#     question_site = question_site_name + "." + question_site_domain
#     offset = offset + 2 + packet[offset]
#     question_type, question_class = struct.unpack('!HH', packet[offset:offset + 4])
#
#     QR, OPCODE, AA, TC, RD, Z, RCODE = decode_flag(flags)
#
#     decoded_packet['header'] = {
#         'ID': header_id,  # Initialize with the header_id variable
#         'QR': QR,
#         'OPCODE': OPCODE,
#         'AA': AA,
#         'TC': TC,
#         'RD': RD,
#         'Z': Z,
#         'RCODE': 0,
#         'QDCOUNT': qd_count,  # Initialize with the QDCOUNT variable
#         'ANCOUNT': an_count,  # Initialize with the ANCOUNT variable
#         'NSCOUNT': ns_count,
#         'ARCOUNT': ar_count
#     }
#
#     decoded_packet['question'] = {
#         'Name': question_site,
#         'Type': question_type,
#         'Class': question_class
#     }
#
#     return decoded_packet

import struct


def decode_dns(packet: bytes):
    decoded_packet: dict = {}
    header_length = 12

    # Unpack header fields
    headers = struct.unpack('!HHHHHH', packet[:header_length])
    header_id, flags, qd_count, an_count, ns_count, ar_count = headers

    offset = header_length
    question_name = ""

    # Decode the question name
    while True:
        label_length = packet[offset]
        if label_length == 0:
            offset += 1  # Move past the null byte indicating the end of the name
            break
        offset += 1
        question_name += packet[offset:offset + label_length].decode('utf-8') + '.'
        offset += label_length

    question_name = question_name[:-1]  # Remove the trailing dot

    # Unpack question type and class
    question_type, question_class = struct.unpack('!HH', packet[offset:offset + 4])
    offset += 4  # Move past the question type and class

    # Decode flags using your decode_flag function
    QR, OPCODE, AA, TC, RD, Z, RCODE = decode_flag(flags)

    # Construct the decoded packet dictionary
    decoded_packet['header'] = {
        'ID': header_id,
        'QR': QR,
        'OPCODE': OPCODE,
        'AA': AA,
        'TC': TC,
        'RD': RD,
        'Z': Z,
        'RCODE': RCODE,
        'QDCOUNT': qd_count,
        'ANCOUNT': an_count,
        'NSCOUNT': ns_count,
        'ARCOUNT': ar_count
    }

    decoded_packet['question'] = {
        'Name': question_name,
        'Type': question_type,
        'Class': question_class
    }

    return decoded_packet


def decode_flag(flag: int):
    QR = (flag >> 15) & 0b1

    # Extract OPCODE (4 bits from the 11th–14th positions)
    OPCODE = (flag >> 11) & 0b1111

    # Extract AA (1 bit at the 10th position)
    AA = (flag >> 10) & 0b1

    # Extract TC (1 bit at the 9th position)
    TC = (flag >> 9) & 0b1

    # Extract RD (1 bit at the 8th position)
    RD = (flag >> 8) & 0b1

    # Extract RCODE (4 bits from the 0th–3rd positions)
    RCODE = flag & 0b1111

    Z = (flag >> 4) & 0b111

    return QR, OPCODE, AA, TC, RD, Z, RCODE


def decode_answer(buffer, offset):
    """
    Decodes a DNS answer from the given buffer, starting at the specified offset.

    Args:
        buffer (bytes): The DNS packet in bytes.
        offset (int): The starting position of the answer section in the buffer.

    Returns:
        dict: Decoded DNS answer fields with NAME, TYPE, CLASS, TTL, and RDATA.
    """
    answer = {}

    # Decode NAME (usually a pointer, so read 2 bytes)
    # If NAME is a pointer, its first two bits are `11` (0xC0 in hex).
    name_pointer = struct.unpack_from("!H", buffer, offset)[0]
    if name_pointer & 0xC000 == 0xC000:  # Check if it's a pointer
        pointer_offset = name_pointer & 0x3FFF  # Get the offset without the 2-bit prefix
        answer['NAME'] = decode_name(buffer, pointer_offset)
        offset += 2  # Move offset by 2 bytes (pointer length)
    else:
        answer['NAME'], offset = decode_name(buffer, offset, return_offset=True)

    # Decode TYPE (2 bytes) and CLASS (2 bytes)
    answer['TYPE'], answer['CLASS'] = struct.unpack_from("!HH", buffer, offset)
    offset += 4

    # Decode TTL (4 bytes)
    answer['TTL'] = struct.unpack_from("!I", buffer, offset)[0]
    offset += 4

    # Decode RDLENGTH (2 bytes)
    rdlength = struct.unpack_from("!H", buffer, offset)[0]
    offset += 2

    # Decode RDATA (variable length, defined by RDLENGTH)
    if answer['TYPE'] == 1:  # A record, IPv4 address
        answer['RDATA'] = ".".join(map(str, buffer[offset:offset + rdlength]))
    elif answer['TYPE'] == 28:  # AAAA record, IPv6 address
        answer['RDATA'] = ":".join(f"{buffer[i]:02x}{buffer[i + 1]:02x}" for i in range(offset, offset + rdlength, 2))
    else:
        answer['RDATA'] = buffer[offset:offset + rdlength]  # For other types, just store the raw data
    offset += rdlength

    return answer, offset

def decode_name(buffer, offset, return_offset=False):
    """Helper function to decode domain names, handling compression pointers."""
    labels = []
    while True:
        length = buffer[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            pointer_offset = ((length & 0x3F) << 8) | buffer[offset + 1]
            labels.append(decode_name(buffer, pointer_offset)[0])
            offset += 2
            break
        else:
            offset += 1
            labels.append(buffer[offset:offset + length].decode())
            offset += length
    return ".".join(labels), offset if return_offset else ".".join(labels)