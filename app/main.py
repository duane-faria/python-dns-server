import socket

from app.message import DNSHeader

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            message = DNSHeader()
            message.ID = 1234
            message.QR = 1
            message.OPCODE = 0
            message.AA = 0
            message.TC = 0
            message.RD = 0
            message.Z = 0
            message.RCODE = 0
            message.QDCOUNT = 0
            message.ANCOUNT = 0
            message.NSCOUNT = 0
            message.ARCOUNT = 0

            response = message.convert_into_packet()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
