import pandas as pd
import numpy as np
import joblib
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# --- 설정 ---
# 업로드된 파일 목록
FILE_LIST = [
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv"
]
# 저장할 모델 및 스케일러 파일 이름
MODEL_PATH = 'random_forest_model.joblib'
SCALER_PATH = 'min_max_scaler.joblib'
LABEL_ENCODER_PATH = 'label_encoder.joblib'
FEATURE_NAMES_PATH = 'feature_names.joblib'

# --- 1. 데이터 통합 및 클리닝 ---

def load_and_clean_data(file_list):
    """CSV 파일들을 통합하고 데이터를 정리합니다."""
    all_data = []
    print("데이터 파일 통합 중...")
    
    base_dir = os.path.dirname(os.path.abspath(__file__)) if '__file__' in locals() else os.getcwd()

    for file in file_list:
        file_path = os.path.join(base_dir, file)
        try:
            # 파일 로드 시, 모든 컬럼을 문자열로 먼저 로드하여 오류 방지
            df = pd.read_csv(file_path, low_memory=False)
            all_data.append(df)
        except FileNotFoundError:
            print(f"오류: {file} 파일을 찾을 수 없습니다. 경로를 확인해주세요.")
            return None, None
    
    df = pd.concat(all_data, ignore_index=True)
    
    # 컬럼 이름의 공백 및 불필요한 문자 제거
    df.columns = df.columns.str.strip().str.replace(' ', '_').str.replace('/', '_')
    
    # 'Flow_ID'와 'Timestamp' 컬럼이 있다면 제거
    cols_to_drop = ['Flow_ID', 'Timestamp', 'Source_IP', 'Destination_IP', 'Source_Port'] 
    df.drop(columns=[col for col in cols_to_drop if col in df.columns], errors='ignore', inplace=True)
    
    # 숫자가 아닌 데이터가 있는 컬럼을 제외하고 모든 컬럼을 float로 변환 시도
    numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
    
    # 숫자형이 아닌 컬럼 중 'Label'을 제외하고 제거
    non_numeric_cols = [col for col in df.columns if col not in numeric_cols and col != 'Label']
    df.drop(columns=non_numeric_cols, errors='ignore', inplace=True)
    
    # Infinity 값 처리 (많은 Flow/s 컬럼에서 발생)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # NaN 값 처리: 결측치가 있는 행 제거
    df.dropna(inplace=True)
    
    # 레이블 컬럼이 유일한 비수치형 컬럼이어야 함
    X = df.drop(columns=['Label'], errors='ignore')
    y = df['Label']
    
    print(f"최종 통합 데이터 크기: {df.shape}")
    return X, y

# --- 2. 특징 스케일링 및 레이블 인코딩 ---

def preprocess_features_labels(X, y):
    """특징 스케일링 및 레이블 인코딩을 수행합니다."""
    
    # 1. 레이블 통합 및 인코딩
    # Web Attack 하위 분류를 'Web Attack'으로 통합
    y_clean = y.replace({
        'Web Attack - Sql Injection': 'Web Attack', 
        'Web Attack - Brute Force': 'Web Attack', 
        'Web Attack - XSS': 'Web Attack'
    })
    
    # 레이블 인코더 초기화 및 훈련
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_clean)
    print(f"총 {len(le.classes_)}개의 고유 레이블: {le.classes_}")
    
    # 2. 특징 스케일링 (MinMaxScaler)
    scaler = MinMaxScaler()
    # 특징 순서 보장을 위해 DataFrame 형태를 유지
    X_scaled = scaler.fit_transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=X.columns)
    
    # 특징 이름 순서 저장 (API 입력 시 순서 보장용)
    feature_names = X.columns.tolist()

    return X_scaled_df, y_encoded, scaler, le, feature_names

# --- 3. 모델 훈련 및 저장 ---

def train_and_save_model(X_df, y_encoded, scaler, le, feature_names):
    """Random Forest 모델을 훈련하고 결과물들을 저장합니다."""
    
    # 훈련/테스트 세트 분할 (20% 테스트 세트)
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # Random Forest 모델 훈련
    print("\nRandom Forest 모델 훈련 시작...")
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    print("Random Forest 모델 훈련 완료.")
    
    # 모델 평가
    y_pred = model.predict(X_test)
    
    print("\n--- 모델 평가 결과 ---")
    print(f"정확도 (Accuracy): {accuracy_score(y_test, y_pred):.4f}")
    # 상세 분류 보고서 (원본 레이블 이름으로 변환하여 출력)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print("----------------------")
    
    # 모델, 스케일러, 인코더, 특징 이름 저장
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(le, LABEL_ENCODER_PATH)
    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    
    print(f"\n✅ 모델 파일 저장 완료: {MODEL_PATH}, {SCALER_PATH}, {LABEL_ENCODER_PATH}, {FEATURE_NAMES_PATH}")


if __name__ == "__main__":
    X, y = load_and_clean_data(FILE_LIST)
    if X is None:
        exit()
        
    X_processed, y_encoded, scaler, le, feature_names = preprocess_features_labels(X, y)
    train_and_save_model(X_processed, y_encoded, scaler, le, feature_names)



