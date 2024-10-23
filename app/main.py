import socket

from app.entities import DNSHeader, DNSQuestion, DNSAnswer

def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    domain_name = 'codecrafters.io'

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(buf, 'buf')
            header = DNSHeader()
            header.ID = 1234
            header.QDCOUNT = 1
            header.ANCOUNT = 1

            question = DNSQuestion()
            question.Name = domain_name

            answer = DNSAnswer()
            answer.Name = domain_name

            response = header.convert_to_bytes() + question.convert_to_bytes() + answer.convert_to_bytes()

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
