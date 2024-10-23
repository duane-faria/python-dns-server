def convert_domain_name(domain: str):
    domain_parts = domain.split('.')
    labels = b''

    for part in domain_parts:
        if len(part) == 0:
            continue
        labels += len(part).to_bytes(1, 'big') + part.encode('utf-8')
    labels += b'\x00'

    return labels