import struct

class DNSMessage:
    def convert_to_bytes(self):
        pass

class DNSHeader(DNSMessage):
    ID: int
    QR: int
    OPCODE: int
    AA: int
    TC: int
    RD: int
    Z: int
    RCODE: int
    QDCOUNT: int
    ANCOUNT: int
    NSCOUNT: int
    ARCOUNT: int

    def convert_to_bytes(self):
        flags = (self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | \
                (self.TC << 9) | (self.RD << 8) | (0 << 7) | (0 << 6) | \
                (0 << 5) | (0 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | self.RCODE

        byte_data = struct.pack('!HHHHHH', self.ID, flags, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)

        return byte_data


class DNSQuestion(DNSMessage):
    Name: str
    Type: int
    Class: int

    def convert_to_bytes(self) -> struct:
        domain_parts = self.Name.split('.')
        labels = b''

        for part in domain_parts:
            if len(part) == 0:
                continue
            labels += len(part).to_bytes(1, 'big') + part.encode('utf-8')
        labels += b'\x00'

        return labels + struct.pack('!HH', self.Type, self.Class)
