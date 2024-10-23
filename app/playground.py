import struct

def encode_dns_query():
    # DNS Header
    ID = 1234
    FLAGS = 0x0100  # Standard query
    QDCOUNT = 1     # One question
    ANCOUNT = 0     # No answers
    NSCOUNT = 0     # No authority records
    ARCOUNT = 0     # No additional records

    # Pack the header fields
    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # DNS Question
    domain_name = 'codecrafters.io'
    labels = domain_name.split('.')
    encoded_name = b''.join([len(label).to_bytes(1, 'big') + label.encode('utf-8') for label in labels])
    encoded_name += b'\x00'  # End of the domain name

    TYPE = 1  # A record
    CLASS = 1  # IN (Internet)

    # Pack the question fields
    question = encoded_name + struct.pack('!HH', TYPE, CLASS)

    # Combine header and question to form the complete DNS query
    dns_query = header + question

    return dns_query

# Get the encoded DNS query
dns_query_bytes = encode_dns_query()
print(dns_query_bytes)
