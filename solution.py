import socket
import sys

def parse_email(file_path):
    """
    Read file and return (sender, recipient, subject, body).
    Validate that sender and recipient include '@'.
    On any parsing/validation error, raise SystemExit(1).
    """
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Split headers and body
        lines = content.split('\n')
        sender = None
        recipient = None
        subject = None
        body_start = -1
        
        # Parse headers
        for i, line in enumerate(lines):
            if line.startswith('From: '):
                sender = line[6:].strip()
            elif line.startswith('To: '):
                recipient = line[4:].strip()
            elif line.startswith('Subject: '):
                subject = line[9:].strip()
            elif line.strip() == '':
                # Empty line marks end of headers
                body_start = i + 1
                break
        
        # Validate required fields
        if not sender or '@' not in sender:
            raise ValueError("Invalid sender")
        if not recipient or '@' not in recipient:
            raise ValueError("Invalid recipient")
        if subject is None:
            subject = ""
        
        # Extract body
        if body_start >= 0:
            body = '\n'.join(lines[body_start:])
        else:
            body = ""
        
        return (sender, recipient, subject, body)
    
    except Exception as e:
        raise SystemExit(1)

def build_dns_query(id, domain, qtype):
    """
    Build bytes: ID(1) + QNAME + QTYPE(1)
    QNAME = label_len(1) + label_bytes ... + 0x00
    """
    query = bytes([id])
    
    # Build QNAME from domain
    labels = domain.split('.')
    for label in labels:
        label_bytes = label.encode('ascii')
        query += bytes([len(label_bytes)]) + label_bytes
    
    # Terminate with null byte
    query += bytes([0x00])
    
    # Add QTYPE
    query += bytes([qtype])
    
    return query

def send_dns_query(dns_ip, query):
    """
    Send UDP to (dns_ip, 1053), return response bytes (use timeout).
    On error or timeout, raise SystemExit(1).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)  # 5 second timeout
        
        sock.sendto(query, (dns_ip, 1053))
        response, _ = sock.recvfrom(4096)
        
        sock.close()
        return response
    
    except Exception as e:
        raise SystemExit(1)

def parse_dns_response(response, expected_id, qtype):
    """
    Validate response[0] == expected_id, parse QNAME echo,
    read QCODE (0 success / 1 error), then ANSWER_LEN(1) and ANSWER.
    For MX (qtype=15): ANSWER is label-encoded hostname ending with 0x00.
    For A  (qtype=1):  ANSWER is 4 bytes IPv4. Return 'a.b.c.d'.
    On any error, raise SystemExit(1).
    """
    try:
        if len(response) < 2:
            raise ValueError("Response too short")
        
        # Validate ID
        if response[0] != expected_id:
            raise ValueError("ID mismatch")
        
        # Skip QNAME echo (find the null terminator)
        pos = 1
        while pos < len(response) and response[pos] != 0x00:
            label_len = response[pos]
            pos += 1 + label_len
        pos += 1  # Skip null byte
        
        # Read QCODE
        if pos >= len(response):
            raise ValueError("Missing QCODE")
        qcode = response[pos]
        pos += 1
        
        # Check for error
        if qcode != 0:
            # Read error message
            if pos >= len(response):
                raise ValueError("DNS error")
            answer_len = response[pos]
            pos += 1
            error_msg = response[pos:pos+answer_len].decode('ascii')
            raise ValueError(f"DNS error: {error_msg}")
        
        # Read ANSWER_LEN
        if pos >= len(response):
            raise ValueError("Missing ANSWER_LEN")
        answer_len = response[pos]
        pos += 1
        
        # Parse ANSWER based on qtype
        if qtype == 15:
            # Parse label-encoded hostname
            hostname_parts = []
            answer_pos = pos
            while answer_pos < len(response) and response[answer_pos] != 0x00:
                label_len = response[answer_pos]
                answer_pos += 1
                if answer_pos + label_len > len(response):
                    raise ValueError("Invalid MX format")
                label = response[answer_pos:answer_pos+label_len].decode('ascii')
                hostname_parts.append(label)
                answer_pos += label_len
            return '.'.join(hostname_parts)
        
        elif qtype == 1:
            # Parse 4-byte IPv4
            if answer_len != 4 or pos + 4 > len(response):
                raise ValueError("Invalid A record format")
            ip_parts = [str(response[pos+i]) for i in range(4)]
            return '.'.join(ip_parts)
        
        else:
            raise ValueError("Unsupported qtype")
    
    except Exception as e:
        raise SystemExit(1)

def send_smtp_email(ip, sender, recipient, subject, body):
    """
    Connect TCP to (ip, 1025). Exchange lines with '\n' endings:
      - read '220 ...'
      - send 'HELO <send_domain>'
      - 'MAIL FROM: <sender>'
      - 'RCPT TO: <recipient>'
      - 'DATA' then body, '.', expect '250'
      - 'QUIT', expect '221'
    On any error, raise SystemExit(1).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect((ip, 1025))
        
        # Helper function to receive a line
        def recv_line():
            data = b''
            while b'\n' not in data:
                chunk = sock.recv(1024)
                if not chunk:
                    raise ValueError("Connection closed")
                data += chunk
            return data.decode('ascii').strip()
        
        # Helper function to send a line
        def send_line(line):
            sock.sendall((line + '\n').encode('ascii'))
        
        # Read 220 greeting
        response = recv_line()
        if not response.startswith('220'):
            raise ValueError(f"Expected 220, got: {response}")
        
        # Send HELO with sender domain
        send_domain = sender.split('@')[1]
        send_line(f'HELO {send_domain}')
        response = recv_line()
        if not response.startswith('250'):
            raise ValueError(f"HELO failed: {response}")
        
        # Send MAIL FROM
        send_line(f'MAIL FROM: {sender}')
        response = recv_line()
        if not response.startswith('250'):
            raise ValueError(f"MAIL FROM failed: {response}")
        
        # Send RCPT TO
        send_line(f'RCPT TO: {recipient}')
        response = recv_line()
        if not response.startswith('250'):
            raise ValueError(f"RCPT TO failed: {response}")
        
        # Send DATA
        send_line('DATA')
        response = recv_line()
        if not response.startswith('354'):
            raise ValueError(f"DATA failed: {response}")
        
        # Send body line by line, then terminator
        for line in body.split('\n'):
            send_line(line)
        send_line('.')
        response = recv_line()
        if not response.startswith('250'):
            raise ValueError(f"Message not accepted: {response}")
        
        # Send QUIT
        send_line('QUIT')
        response = recv_line()
        if not response.startswith('221'):
            raise ValueError(f"QUIT failed: {response}")
        
        sock.close()
    
    except Exception as e:
        raise SystemExit(1)

if __name__ == '__main__':
    # Accept either: script email_file  OR script email_file dns_ip
    if len(sys.argv) not in (2, 3):
        raise SystemExit(1)
    file_path = sys.argv[1]
    dns_ip = sys.argv[2] if len(sys.argv) > 2 else '127.0.0.1'

    sender, recipient, subject, body = parse_email(file_path)
    domain = recipient.split('@')[1]

    mx_query = build_dns_query(18, domain, 15)    # MX
    mx_response = send_dns_query(dns_ip, mx_query)
    mx_host = parse_dns_response(mx_response, 18, 15)

    a_query = build_dns_query(19, mx_host, 1)     # A
    a_response = send_dns_query(dns_ip, a_query)
    ip = parse_dns_response(a_response, 19, 1)

    send_smtp_email(ip, sender, recipient, subject, body)