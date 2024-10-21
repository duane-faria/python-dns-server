import socket

from app.message import DNSHeader, DNSQuestion


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    counter = 0
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            header = DNSHeader()
            header.ID = 1234
            header.QR = 1
            header.OPCODE = 0
            header.AA = 0
            header.TC = 0
            header.RD = 0
            header.Z = 0
            header.RCODE = 0
            header.QDCOUNT = counter
            header.ANCOUNT = 0
            header.NSCOUNT = 0
            header.ARCOUNT = 0

            question = DNSQuestion()
            question.Name = 'codecrafters.io'
            question.Type = 1
            question.Class = 1

            response = header.convert_to_bytes() + question.convert_to_bytes()
            print(response)
            counter += 1
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
