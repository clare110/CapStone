# 참고 사항
- `suricata_tcp_relay.py`, `flow_extractor.py`, `rule_command_client.py`는 `Suricata`의 환경에서 실행
- `flow_extractor.py`는 관리자 권한으로 실행

- `ml_api_server.py`는 `ML` 및 `LLM`의 환경에서 실행
- `train_model.py`는 확장자가 `.joblib`인 파일이 없거나, 적용되지 않을 경우 실행
- `train_model.py` 실행 시 데이터 파일이 있어야 함
- 본인의 경우 첫 모델 학습에서 `Kaggle`에 있는 `CIC-IDS2017`를 사용함

# 주의 점
- 각 파일의 주소 부분을 모두 환경에 맞게 수정해주어야 함
- 본인의 경우 윈도우 PC에 ML을, 윈도우 PC의 WSL에 LLM을 구성하였고, ML과 LLM은 같은 IP 대역을 가졌음 (주소는 다름)
- `Suricata`의 환경에서 `10001`과 `10002` 포트를 방화벽(ufw)에서 허용 해주어야 함
