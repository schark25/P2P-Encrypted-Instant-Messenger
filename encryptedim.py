import argparse
import socket
import select
import sys
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# HOST = '127.0.0.1'
PORT = 9999


def create_cipher(key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher

def encrypt_and_hmac(message, confkey, authkey):
    iv = get_random_bytes(AES.block_size)
    cipher = create_cipher(confkey, iv)
    
    message_len_padded = pad(len(message).to_bytes(8, byteorder='big'), AES.block_size)
    encrypted_len = cipher.encrypt(message_len_padded)
    
    message_padded = pad(message, AES.block_size)
    encrypted_msg = cipher.encrypt(message_padded)
    
    hmac_len = HMAC.new(authkey, iv + encrypted_len, SHA256).digest()
    hmac_msg = HMAC.new(authkey, encrypted_msg, SHA256).digest()
    return iv + encrypted_len + hmac_len + encrypted_msg + hmac_msg

def decrypt_and_verify(data, confkey, authkey):
    iv_size = AES.block_size
    hmac_size = SHA256.digest_size
    encrypted_len_size = AES.block_size
    
    iv = data[:iv_size]

    encrypted_len = data[iv_size:iv_size + encrypted_len_size]
    hmac_len = data[iv_size + encrypted_len_size:iv_size + encrypted_len_size + hmac_size]
    encrypted_msg_start = iv_size + encrypted_len_size + hmac_size
    encrypted_msg = data[encrypted_msg_start:-hmac_size]
    hmac_msg = data[-hmac_size:]
    
    if HMAC.new(authkey, iv + encrypted_len, SHA256).digest() != hmac_len:
        raise ValueError("ERROR: HMAC verification failed")
    if HMAC.new(authkey, encrypted_msg, SHA256).digest() != hmac_msg:
        raise ValueError("ERROR: HMAC verification failed")
    
    cipher = create_cipher(confkey, iv)
    decrypted_len = unpad(cipher.decrypt(encrypted_len), AES.block_size)
    message_len = int.from_bytes(decrypted_len, byteorder='big')
    
    decrypted_msg = unpad(cipher.decrypt(encrypted_msg), AES.block_size)
    
    decrypted_msg = decrypted_msg[:message_len]
    
    return decrypted_msg.decode()


def run_server(aes_key, hmac_key):
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('', PORT))
    listen_socket.listen()
    client_sockets = []
    while True:
        read_list = [listen_socket] + client_sockets + [sys.stdin]
        (ready_read, _, _) = select.select(read_list, [], [])

        for sock in ready_read:
            if sock is listen_socket:
                new_conn, addr = sock.accept()
                client_sockets.append(new_conn)
            elif sock is sys.stdin:
                input = sys.stdin.readline().encode('utf-8')
                if not input:
                    listen_socket.close()
                    for c in client_sockets :
                        c.close()
                    return
                for c in client_sockets:
                    #encrypt here?
                    encyrptedMessage = encrypt_and_hmac(input, aes_key, hmac_key)
                    c.sendall(encyrptedMessage)
            else:
                data = sock.recv(4096)
                if data != b'':
                    try:
                        new_data = decrypt_and_verify(data, aes_key, hmac_key)
                        sys.stdout.write(new_data)
                        sys.stdout.flush()
                    except ValueError as e:
                        print(e)
                        sock.close()
                        sys.exit(1)
                else:
                    client_sockets.remove(sock)
                    sock.close()

def run_client(hostname, aes_key, hmac_key):
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((hostname, PORT))
    try:
        while True:
            input_list = [conn_sock, sys.stdin]
            try:
                (ready_read, _, _) = select.select(input_list, [], [])
            except ValueError:
                break

            for sock in ready_read:
                if sock is conn_sock:
                    data = sock.recv(4096)
                    if data:
                        try:
                            new_data = decrypt_and_verify(data, aes_key, hmac_key)
                            sys.stdout.write(new_data)
                            sys.stdout.flush()
                        except ValueError as e:
                            print(e)
                            sock.close()
                            sys.exit(1)
                    else:
                        # client_sockets.remove(sock)
                        sock.close()
                elif sock is sys.stdin:
                    input = sys.stdin.readline().encode('utf-8')
                    if not input:
                        conn_sock.close()
                        return
                    encyrptedMessage = encrypt_and_hmac(input, aes_key, hmac_key)
                    conn_sock.sendall(encyrptedMessage)
    except KeyboardInterrupt:
        conn_sock.close()
        sys.exit(0)
        

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--server", "--s", action="store_true", help="Start in server mode (waits for incoming connections).")
    group.add_argument("--client", "--c", metavar="hostname", type=str, help="Start in client mode and connect to the specified hostname.")
    parser.add_argument("--confkey", metavar="K1", required=True, type=str, help="Specifies the confidentiality key used for encryption.")
    parser.add_argument("--authkey", metavar="K2", required=True, type=str, help="Specifies the authenticity key used to compute the HMAC.")
    args = parser.parse_args()

    confkey = SHA256.new(args.confkey.encode()).digest()
    authkey = SHA256.new(args.authkey.encode()).digest()

    if args.server:
        run_server(confkey, authkey)
    elif args.client:
        if args.client == "":
            raise Exception("--c flag requires a hostname argument")
        else:
            run_client(args.client, confkey, authkey)


if __name__ == '__main__':
    main()