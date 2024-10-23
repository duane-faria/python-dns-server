import struct

from app.entities.dns_partial import DNSPart
from app.utils.dns import convert_domain_name

class DNSQuestion(DNSPart):
    Name: str
    Type: int = 1
    Class: int = 1

    def convert_to_bytes(self) -> struct:
        labels = convert_domain_name(self.Name)
        return labels + struct.pack('!HH', self.Type, self.Class)
