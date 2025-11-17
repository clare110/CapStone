import socket
import json
import sys

# =========================================================
# 1. 환경 설정 (Configuration)
# =========================================================
CLIENT_LISTEN_IP = '0.0.0.0'
CLIENT_LISTEN_PORT = 10002
RELAY_SERVER_IP = '127.0.0.1' 
RELAY_SERVER_PORT = 10001
RELAY_TIMEOUT = 5

# =========================================================
# 2. Suricata Relay 통신 함수
# =========================================================

def send_to_suricata_relay(command_json):
    try:
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        relay_sock.settimeout(RELAY_TIMEOUT)
        relay_sock.connect((RELAY_SERVER_IP, RELAY_SERVER_PORT))
    except socket.error as e:
        return {"return": "KO", "message": f"Relay Communication Failed: [Errno {e.errno}] {e.strerror}"}
    
    try:
        command_str = json.dumps(command_json, ensure_ascii=False)
        command_to_send = (command_str.strip() + '\n').encode('utf-8')
        relay_sock.sendall(command_to_send)
    except socket.error as e:
        return {"return": "KO", "message": f"Relay Send Failed: [Errno {e.errno}] {e.strerror}"}
    
    try:
        response_data = relay_sock.recv(4096)
        if not response_data:
            return {"return": "KO", "message": "Suricata Error: Response data is empty"}
        response_json = json.loads(response_data.decode('utf-8').strip())
        return response_json
    except Exception as e:
        return {"return": "KO", "message": f"Relay Response Error: {str(e)}"}
    finally:
        relay_sock.close()

# =========================================================
# 3. 명령 처리 함수
# =========================================================

def process_add_rule_command(data):
    if not all(k in data for k in ['rule', 'sid']):
        return {"return": "KO", "message": "ADD_RULE requires 'rule' and 'sid'."}

    suricata_command = {"command": "rule-add", "rule": data['rule'], "sid": data['sid']}
    relay_response = send_to_suricata_relay(suricata_command)
    
    if relay_response.get("return") == "OK":
        print(f"✅ Rule ADD 성공 (SID {data['sid']})")
        return {"return": "OK", "message": f"Rule ADD Success: {relay_response.get('message')}"}
    else:
        error_message = relay_response.get('message', 'Unknown error during rule add.')
        print(f"❌ Rule ADD 실패 (SID {data['sid']}): {error_message}")
        return {"return": "KO", "message": f"Rule ADD Failed: {error_message}"}

def handle_client_connection(client_socket):
    try:
        request = client_socket.recv(4096)
        if not request: return
        
        try:
            data = json.loads(request.decode('utf-8').strip())
        except json.JSONDecodeError:
            response = {"return": "KO", "message": "Invalid JSON format."}
            client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')
            return

        command_type = data.get("type")
        if command_type == "ADD_RULE":
            response = process_add_rule_command(data)
        else:
            response = {"return": "KO", "message": f"Unknown command type: {command_type}"}

        client_socket.sendall(json.dumps(response).encode('utf-8') + b'\n')

    except Exception as e:
        print(f"❌ 클라이언트 처리 중 예외 발생: {e}")
    finally:
        client_socket.close()
        print("INFO: Client connection closed.")


def start_command_client():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((CLIENT_LISTEN_IP, CLIENT_LISTEN_PORT))
        server_socket.listen(5)
        print(f"🚀 Rule Command Client 시작: {CLIENT_LISTEN_IP}:{CLIENT_LISTEN_PORT}")
    except socket.error as e:
        print(f"❌ 서버 바인딩 오류: [Errno {e.errno}] {e.strerror}")
        sys.exit(1)

    while True:
        try:
            client_sock, addr = server_socket.accept()
            print(f"INFO: 명령 연결 수락 - {addr[0]}:{addr[1]}")
            handle_client_connection(client_sock)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ 연결 수락 중 예외 발생: {e}")
            continue

if __name__ == '__main__':
    start_command_client()