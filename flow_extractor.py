import json
import time
import os
import sys

# =========================================================
# 1. 환경 설정 (Configuration)
# =========================================================
EVE_LOG_PATH = '/var/log/suricata/eve.json'
MIN_FLOW_AGE = 5  # 초 단위
TARGET_FLOW_STATES = ['established', 'closed'] 

# =========================================================
# 2. 플로우 추출 및 처리 함수
# =========================================================

def extract_flow_features(log_entry):
    """ EVE JSON 로그 엔트리에서 핵심 플로우 정보를 추출합니다. """
    
    if log_entry.get("event_type") != "flow" or "flow" not in log_entry:
        return None
    
    flow_data = log_entry["flow"]
    
    if flow_data.get("state") not in TARGET_FLOW_STATES:
        return None
    
    if flow_data.get("age") is not None and flow_data["age"] < MIN_FLOW_AGE:
        return None

    extracted_features = {
        "timestamp": log_entry.get("timestamp"),
        "flow_id": log_entry.get("flow_id"),
        "proto": log_entry.get("proto"),
        "src_ip": log_entry.get("src_ip"),
        "dest_ip": log_entry.get("dest_ip"),
        "src_port": log_entry.get("src_port"),
        "dest_port": log_entry.get("dest_port"),
        "flow_state": flow_data.get("state"),
        "flow_age": flow_data.get("age"),
        "pkts_toserver": flow_data.get("pkts_toserver"),
        "pkts_toclient": flow_data.get("pkts_toclient"),
        "bytes_toserver": flow_data.get("bytes_toserver"),
        "bytes_toclient": flow_data.get("bytes_toclient"),
    }
    
    return extracted_features


def stream_eve_log():
    """ EVE JSON 로그 파일을 실시간으로 모니터링하며 데이터를 추출합니다. """
    if not os.path.exists(EVE_LOG_PATH):
        print(f"❌ 오류: EVE 로그 파일을 찾을 수 없습니다: {EVE_LOG_PATH}")
        sys.exit(1)

    print(f"🚀 Flow Extractor 시작: {EVE_LOG_PATH} 파일을 모니터링합니다...")
    
    try:
        # tail -f 모드를 위한 파일 열기
        logfile = open(EVE_LOG_PATH, 'r')
        logfile.seek(0, os.SEEK_END)
    except Exception as e:
        print(f"❌ 파일 열기 오류: {e}")
        sys.exit(1)

    while True:
        line = logfile.readline()
        
        if not line:
            time.sleep(0.1)
            continue
        
        try:
            log_entry = json.loads(line.strip())
            flow_features = extract_flow_features(log_entry)
            
            if flow_features:
                # ----------------------------------------------------
                # 🚨 ML/LLM으로 데이터 전송 로직 🚨
                # (이 부분에서 추출된 flow_features를 환경 2로 전송해야 함)
                # ----------------------------------------------------
                
                # TODO: TCP 또는 UDP 소켓을 사용하여 환경 2의 ML/LLM 서버로 데이터를 전송하는 로직을 추가해야 합니다.
                print(f"✅ Extracted Flow: {flow_features['timestamp']} | {flow_features['src_ip']} -> {flow_features['dest_ip']}")
                
        except json.JSONDecodeError:
            print(f"⚠️ JSON 파싱 건너뜀: 손상된 로그 라인 감지")
        except Exception as e:
            print(f"❌ 알 수 없는 처리 오류: {e}")
            
# =========================================================
# 3. 메인 실행
# =========================================================

if __name__ == '__main__':
    try:
        stream_eve_log()
    except KeyboardInterrupt:
        print("\n👋 Flow Extractor 종료.")