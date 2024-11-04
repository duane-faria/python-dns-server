import struct
from dataclasses import dataclass

from app.entities.dns_partial import DNSPart

@dataclass
class DNSHeader(DNSPart):
    ID: int
    QR: int = 1
    OPCODE: int = 0
    AA: int = 0
    TC: int = 0
    RD: int = 0
    Z: int = 0
    RCODE: int = 0
    QDCOUNT: int = 1
    ANCOUNT: int = 1
    NSCOUNT: int = 0
    ARCOUNT: int = 0

    def convert_to_bytes(self):
        flags = (self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | \
                (self.TC << 9) | (self.RD << 8) | (0 << 7) | (0 << 6) | \
                (0 << 5) | (0 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | self.RCODE

        byte_data = struct.pack('!HHHHHH', self.ID, flags, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)

        return byte_data

    @classmethod
    def from_packet(cls, packet):
        """Creates a DNSHeader instance from a decoded packet dictionary."""
        header = cls(
            ID=packet.get('ID'),
            QR=1,
            OPCODE=packet.get('OPCODE', 0),
            AA=packet.get('AA', 0),
            TC=packet.get('TC', 0),
            RD=packet.get('RD', 0),
          Z=packet.get('Z', 0),
            RCODE=packet.get('RCODE', 0),
            QDCOUNT=packet.get('QDCOUNT', 1),
            ANCOUNT=1,
            NSCOUNT=packet.get('NSCOUNT', 0),
            ARCOUNT=packet.get('ARCOUNT', 0)
        )
        return header