import struct

class DNSHeader:
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

    def convert_into_packet(self):
        # Create flags according to the DNS message specification
        flags = (self.QR << 15) | (self.OPCODE << 11) | (self.AA << 10) | \
                (self.TC << 9) | (self.RD << 8) | (0 << 7) | (0 << 6) | \
                (0 << 5) | (0 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | self.RCODE

        # Pack the values into a byte string
        byte_data = struct.pack('!HHHHHH', self.ID, flags, self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT)

        return byte_data

