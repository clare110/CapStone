from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np
import warnings
import os
import requests 
import json 
import threading
import socket 

# 경고 메시지 무시
warnings.filterwarnings('ignore', category=UserWarning)

# --- 설정 ---
# 모델 자산 경로
MODEL_PATH = 'random_forest_model.joblib'
SCALER_PATH = 'min_max_scaler.joblib'
LABEL_ENCODER_PATH = 'label_encoder.joblib'
FEATURE_NAMES_PATH = 'feature_names.joblib'
# API 서버 설정
HOST_IP = '0.0.0.0'
PORT = 5000          
# Ollama LLM API 설정 (환경 2 로컬)
OLLAMA_URL = 'http://192.168.0.14:11434/api/generate' 
# Rule Command Client TCP 설정 (환경 1의 10002 포트)
RULE_COMMAND_CLIENT_HOST = '192.168.0.42'
RULE_COMMAND_CLIENT_PORT = 10002

app = Flask(__name__)

# 전역 변수
model = None
scaler = None
le = None
feature_names = None
current_sid = 900000001 
sid_lock = threading.Lock() 

# --- 1. 모델 로드 함수 ---

def load_assets():
    """저장된 모델, 스케일러, 인코더, 특징 이름을 로드합니다."""
    global model, scaler, le, feature_names
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        le = joblib.load(LABEL_ENCODER_PATH)
        feature_names = joblib.load(FEATURE_NAMES_PATH)
        print("✅ 모델 및 자산 로드 완료. 예측 준비 완료.")
        print(f"   예측 특징 개수: {len(feature_names)}")
        return True
    except FileNotFoundError:
        print(f"❌ 오류: 필요한 파일 중 하나를 찾을 수 없습니다. (경로 확인 필요)")
        return False
    except Exception as e:
        print(f"❌ 모델 로드 중 예외 발생: {e}")
        return False

# --- 2. SID 관리 함수 ---

def get_next_sid():
    """Rule SID를 안전하게 증가시키고 반환합니다."""
    global current_sid
    with sid_lock:
        sid = current_sid
        current_sid += 1
        return sid

# --- 3. LLM Rule 생성 함수 (최종 최적화 프롬프트 적용) ---

def generate_suricata_rule(attack_type, flow_features):
    """LLM을 호출하여 최적화된 Suricata Rule을 생성합니다."""
    
    rule_action = "drop" 
    
    # Flow Feature 중 유의미한 값만 프롬프트에 포함 (LLM Context Window 최적화)
    relevant_features = {k: v for k, v in flow_features.items() if v > 0.0 or k in ["Flow_Duration", "Total_Fwd_Packets"]}
    
    # 공격 유형에 따른 추가 힌트 제공
    additional_hints = ""
    if "Web Attack" in attack_type or "Injection" in attack_type or "Fuzzing" in attack_type:
        additional_hints = """
        Rule 옵션: HTTP 기반 공격이므로, 80/443 포트를 명시하고, 공격 시그니처 매칭을 위해 'content' 옵션과 
        안정적인 Flow 추적을 위해 'flowbits:established' 옵션을 반드시 포함하세요. 
        """
    elif "PortScan" in attack_type:
        additional_hints = """
        Rule 옵션: 대량의 연결 시도를 차단해야 하므로, 'threshold' 옵션(예: type limit, track by_src, count 50, seconds 1)을 사용하여 
        임계치 기반의 방어 로직을 구현하세요.
        """

    # 최종 최적화 프롬프트
    prompt = f"""
    당신은 최고 수준의 Suricata 보안 전문가입니다.
    네트워크에서 다음의 **악성 공격**이 탐지되었습니다: **{attack_type}**
    주요 네트워크 Flow Feature 정보입니다: {json.dumps(relevant_features, indent=2)}

    다음 요구사항을 **엄격하게** 충족하는 **단 하나의 최적화된 Suricata Rule 문자열**을 생성하세요:
    1. **액션**: 반드시 **{rule_action}** 액션을 사용합니다.
    2. **Rule 형식**: 오직 Rule 문자열만 출력되어야 합니다. (예: `{rule_action} tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"..."; sid:900000001; rev:1;)`)
    3. **변수**: 내부망 IP는 **`192.168.0.23`** 대신 **`$HOME_NET`** 변수를 사용합니다. 외부망은 **`$EXTERNAL_NET`**을 사용합니다.
    4. **메시지**: 메시지(msg)는 **`"AI_BLOCK:{attack_type}"`** 형태로 시작해야 합니다.
    5. **최적화 옵션**: 공격 유형과 Feature 값을 기반으로 False Positive를 최소화하세요. {additional_hints}
    6. Rule에는 sid:900000001; rev:1; 옵션을 포함해야 합니다.

    Rule:
    """

    data = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1, 
            "max_tokens": 512
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=data)
        response.raise_for_status()
        result = response.json()
        rule_text = result['response'].strip()
        
        # Rule 문자열 정리 로직
        if rule_text.lower().startswith("rule:"):
            rule_text = rule_text[5:].strip()
            
        if not (rule_text.startswith(rule_action) and rule_text.endswith(")")):
            raise ValueError("LLM이 올바른 Suricata Rule 형식을 반환하지 않았습니다.")
            
        return rule_text

    except Exception as e:
        print(f"❌ LLM Rule 생성 중 오류 발생: {e}")
        return None

# --- 4. TCP 전송 함수 (Orchestrator 핵심) ---

def send_rule_command_to_client(command_json):
    """Rule Command Client (환경 1: 10002 포트)로 Rule 명령을 TCP 소켓으로 전송합니다."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3) # 타임아웃 3초 설정
    try:
        sock.connect((RULE_COMMAND_CLIENT_HOST, RULE_COMMAND_CLIENT_PORT))
        
        command_str = json.dumps(command_json)
        # 명령 끝에 개행 문자를 추가하여 Rule Command Client가 명령의 끝을 알 수 있도록 함
        sock.sendall((command_str + "\n").encode('utf-8')) 
        
        print(f"[AI-DR] ➡️ Rule 명령 TCP 전송 완료: {RULE_COMMAND_CLIENT_HOST}:{RULE_COMMAND_CLIENT_PORT}")
        return True
    except socket.timeout:
        print("❌ Rule Command Client 통신 실패: 연결 타임아웃.")
        return False
    except Exception as e:
        print(f"❌ Rule Command Client 통신 실패: {e}. 환경 1의 10002 포트 상태를 확인하세요.")
        return False
    finally:
        sock.close()


# --- 5. 예측 API 엔드포인트 (통합 중앙 제어 로직) ---

@app.route('/predict/flow', methods=['POST'])
def predict_flow():
    """
    Flow Feature를 예측하고, 악성 트래픽인 경우 LLM Rule 생성 및 환경 1로 전송합니다.
    """
    if model is None:
        return jsonify({"error": "모델이 아직 로드되지 않았습니다."}), 500
    
    try:
        data = request.get_json(force=True)
        
        # 1. 데이터 전처리 및 예측
        input_data = {}
        for feature in feature_names:
            # 훈련된 77개 feature 순서 보장 및 누락된 feature는 0.0 처리
            input_data[feature] = data.get(feature.strip().replace('_', ' '), 0.0)

        input_df = pd.DataFrame([input_data], columns=feature_names)
        input_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        input_df.fillna(0, inplace=True) 

        X_scaled = scaler.transform(input_df)
        prediction_encoded = model.predict(X_scaled)[0]
        prediction_proba = model.predict_proba(X_scaled)[0]
        
        predicted_label = le.inverse_transform([prediction_encoded])[0]
        max_proba = np.max(prediction_proba)

        is_malicious = predicted_label != 'BENIGN' 

        response = {
            "status": "success",
            "predicted_attack_type": predicted_label,
            "confidence": f"{max_proba:.4f}",
            "is_malicious": is_malicious 
        }

        # 2. LLM Rule 생성 및 전송 로직
        if is_malicious:
            print(f"\n[AI-DR] 🚨 악성 탐지: {predicted_label}. LLM Rule 생성 요청 중...")
            
            raw_rule = generate_suricata_rule(predicted_label, input_data)
            
            if raw_rule:
                sid = get_next_sid()
                # LLM이 생성한 Rule 문자열에 최종 SID 및 rev를 삽입/교체
                final_rule_string = raw_rule.replace('sid:900000001;', f'sid:{sid};').replace('sid:900000001', f'sid:{sid}').strip()
                
                rule_command = {
                    "type": "ADD_RULE",
                    "rule": final_rule_string,
                    "sid": sid
                }
                
                # TCP 명령 전송
                if send_rule_command_to_client(rule_command):
                    print(f"[AI-DR] ✅ Rule 적용 명령 전송 완료 (SID: {sid}).")
                    response['rule_generation_status'] = "sent"
                    response['generated_rule'] = final_rule_string
                    response['rule_sid'] = sid
                else:
                    response['rule_generation_status'] = "tcp_send_failed"
            else:
                response['rule_generation_status'] = "llm_failed"
                print("[AI-DR] ❌ Rule 생성 실패. Ollama 로그를 확인하세요.")
        
        return jsonify(response)

    except Exception as e:
        print(f"ERROR: 예측 또는 Rule 생성 중 내부 오류 발생: {e}")
        return jsonify({"error": f"예측 또는 Rule 생성 중 내부 오류 발생: {e}"}), 500

# --- 서버 실행 ---
if __name__ == '__main__':
    if load_assets():
        print(f"\n🚀 ML & LLM API 서버 (Orchestrator 통합) 시작: http://{HOST_IP}:{PORT}")
        app.run(host=HOST_IP, port=PORT, debug=False)