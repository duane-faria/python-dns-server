import socket

from app.entities import DNSQuestion, DNSAnswer, DNSHeader
from app.utils.dns import decode_dns


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    domain_name = 'codecrafters.io'
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print('buf', buf)
            packet = decode_dns(buf)

            header = DNSHeader.from_packet(packet.get('header'))

            if header.OPCODE == 0:
                header.RCODE = 0
            else:
               header.RCODE = 4

            print('header: ', header)

            question = DNSQuestion.from_packet(packet.get('question'))
            print('question: ', question)

            answer = DNSAnswer(name=domain_name)

            print('answer', answer.__dict__)

            response = header.convert_to_bytes() + question.convert_to_bytes() + answer.convert_to_bytes()
            print('response', response)
            udp_socket.sendto(response, source)

        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
