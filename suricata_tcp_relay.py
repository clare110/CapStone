import socket
import json
import sys
import os
import time

# =========================================================
# 1. 환경 설정 (Configuration)
# =========================================================
RELAY_LISTEN_IP = '0.0.0.0'
RELAY_LISTEN_PORT = 10001
SURICATA_SOCKET_PATH = '/var/run/suricata/suricata-command.socket'
SURICATA_TIMEOUT = 5

# =========================================================
# 2. Suricata Unix Socket 통신 함수
# =========================================================

def send_command_to_suricata(command_json):
    if not os.path.exists(SURICATA_SOCKET_PATH):
        return {"return": "KO", "message": f"❌ Suricata Socket 파일을 찾을 수 없음: {SURICATA_SOCKET_PATH}"}

    try:
        unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_sock.settimeout(SURICATA_TIMEOUT)
        unix_sock.connect(SURICATA_SOCKET_PATH)
        
    except socket.error as e:
        return {"return": "KO", "message": f"❌ Suricata Socket 연결 오류: [Errno {e.errno}] {e.strerror}"}

    try:
        command_str = json.dumps(command_json, ensure_ascii=False)
        command_to_send = (command_str.strip() + '\n').encode('utf-8')
        unix_sock.sendall(command_to_send)
        
    except socket.error as e:
        unix_sock.close()
        return {"return": "KO", "message": f"❌ Suricata Socket 전송 오류: [Errno {e.errno}] {e.strerror}"}

    response_data = b''
    try:
        while True:
            chunk = unix_sock.recv(4096)
            if not chunk: break
            response_data += chunk
            
        if not response_data:
            return {"return": "KO", "message": "Suricata Error: Response data is empty"}

        response_json = json.loads(response_data.decode('utf-8').strip())
        return response_json
        
    except Exception as e:
        return {"return": "KO", "message": f"❌ Suricata 응답 처리 중 오류 발생: {e}"}
    finally:
        unix_sock.close()

# =========================================================
# 3. 메인 서버 함수
# =========================================================

def handle_client_command(client_socket, client_addr):
    try:
        request = client_socket.recv(4096)
        if not request: return

        try:
            command_data = json.loads(request.decode('utf-8').strip())
        except json.JSONDecodeError:
            response = {"return": "KO", "message": "Invalid JSON format received from client."}
            client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
            return

        suricata_response = send_command_to_suricata(command_data)

        response_to_send = json.dumps(suricata_response, ensure_ascii=False).encode('utf-8') + b'\n'
        client_socket.sendall(response_to_send)

    except Exception as e:
        print(f"❌ 클라이언트 처리 중 예외 발생: {e}")
    finally:
        client_socket.close()
        print("INFO: Client connection closed.")


def start_relay_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((RELAY_LISTEN_IP, RELAY_LISTEN_PORT))
        server_socket.listen(5)
        print(f"🚀 Suricata TCP Relay 시작: {RELAY_LISTEN_IP}:{RELAY_LISTEN_PORT}")
    except socket.error as e:
        print(f"❌ 서버 바인딩 오류: [Errno {e.errno}] {e.strerror}")
        sys.exit(1)

    while True:
        try:
            client_sock, addr = server_socket.accept()
            handle_client_command(client_sock, addr)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ 연결 수락 중 예외 발생: {e}")
            continue

if __name__ == '__main__':
    start_relay_server()