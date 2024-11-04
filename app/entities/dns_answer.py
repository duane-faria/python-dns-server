import struct
import socket

from app.entities.dns_partial import DNSPart
from app.utils.dns import convert_domain_name

class DNSAnswer(DNSPart):
    Name: str
    Type: int = 1
    Class: int = 1
    TTL: int = 60
    Length: int
    Data: str = '8.8.8.8'

    def __init__(self, name):
        self.Name = name
        self.Type: int = 1
        self.Class: int = 1
        self.TTL = 60
        self.Data = '8.8.8.8'

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