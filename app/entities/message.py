import struct
import socket

class DNSPart:
    def convert_to_bytes(self):
        pass


class DNSHeader(DNSPart):
    ID: int
    QR: int = 1
    OPCODE: int = 0
    AA: int = 0
    TC: int = 0
    RD: int = 0
    Z: int = 0
    RCODE: int = 0
    QDCOUNT: int
    ANCOUNT: int
    NSCOUNT: int = 0
    ARCOUNT: int = 0

    def convert_to_bytes(self):
        flags = (self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | \
                (self.TC << 9) | (self.RD << 8) | (0 << 7) | (0 << 6) | \
                (0 << 5) | (0 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | self.RCODE

        byte_data = struct.pack('!HHHHHH', self.ID, flags, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)

        return byte_data


def convert_domain_name(domain: str):
    domain_parts = domain.split('.')
    labels = b''

    for part in domain_parts:
        if len(part) == 0:
            continue
        labels += len(part).to_bytes(1, 'big') + part.encode('utf-8')
    labels += b'\x00'

    return labels


class DNSQuestion(DNSPart):
    Name: str
    Type: int = 1
    Class: int = 1

    def convert_to_bytes(self) -> struct:
        labels = convert_domain_name(self.Name)
        return labels + struct.pack('!HH', self.Type, self.Class)


class DNSAnswer(DNSPart):
    Name: str
    Type: int = 1
    Class: int = 1
    TTL: int = 60
    Length: int
    Data: str = '8.8.8.8'

    def _convert_data_to_bytes(self) -> bytes:
        try:
            data_bytes = socket.inet_aton(self.Data)
            self.Length = len(data_bytes)
            return data_bytes
        except OSError:
            raise ValueError(f"Invalid IP address: {self.Data}")

    def convert_to_bytes(self):
        labels = convert_domain_name(self.Name)
        data_bytes = self._convert_data_to_bytes()
        return labels + struct.pack('!HHIH', self.Type, self.Class, self.TTL, self.Length) + data_bytes