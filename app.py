# --- 필요한 라이브러리(모듈) 불러오기 ---
from flask import Flask, request, jsonify  # Flask 서버 관련
import jwt            # JWT 토큰 생성 관련
import bcrypt         # 비밀번호 암호화 관련
import datetime       # 토큰 만료 시간 설정 관련

# --- 서버 설정 ---

# app이라는 이름의 Flask 서버를 생성합니다.
app = Flask(__name__)

# JWT 토큰을 만들 때 사용할 비밀키입니다. (아무도 모르게 보관해야 함)
app.config['SECRET_KEY'] = 'YOUR_SUPER_SECRET_KEY' 

# (임시) 데이터베이스 대신 파이썬 딕셔너리(변수)를 사용합니다.
# (서버를 껐다 켜면 회원가입한 정보가 사라집니다.)
users = {} 

# --- API 구현 ---

# 1. 회원가입 API (Notion 표의 '회원가입')
# @app.route: "이 주소('/api/v1/auth/signup')로 요청이 오면,"
# methods=['POST']: "POST 방식으로만 받겠다"는 뜻
@app.route('/api/v1/auth/signup', methods=['POST'])
def signup():
    # 프론트가 보낸 데이터를 받습니다.
    data = request.json
    
    email = data.get('email')
    password = data.get('password')
    nickname = data.get('nickname') 

    # (검증) 이미 가입된 이메일인지 확인
    if email in users:
        # 400: Bad Request (잘못된 요청)
        return jsonify({"error": "이미 가입된 이메일입니다."}), 400 

    # (암호화) 비밀번호를 암호화해서 저장합니다.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # (임시 DB에 저장)
    users[email] = {
        'nickname': nickname,
        'password': hashed_password 
    }
    
    print("회원가입 성공:", users) # 님(백엔드 개발자)이 보는 서버 로그
    
    # 201: Created (성공적으로 생성됨)
    return jsonify({"message": "회원가입이 성공적으로 완료되었습니다."}), 201

# 2. 로그인 API (Notion 표의 '로그인(JWT)')
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # (검증 1) 가입된 유저인지 확인
    user = users.get(email)
    
    # (검증 2) 유저가 있고, 암호화된 비밀번호가 일치하는지 확인
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        
        # (토큰 생성) 로그인 성공 시, 1시간 동안 유효한 JWT 토큰 생성
        token = jwt.encode({
            'email': email, 
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1) 
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        # 200: OK (성공)
        return jsonify({'access_token': token}), 200
    else:
        # 401: Unauthorized (인증 실패)
        return jsonify({"error": "이메일 또는 비밀번호가 일치하지 않습니다."}), 401

# --- 서버 실행 ---

# 이 app.py 파일을 직접 실행했을 때(예: 'python app.py') 
# 아래 코드를 실행하라는 의미입니다.
if __name__ == '__main__':
    # 5000번 포트로, 디버그 모드(코드 수정 시 자동 재시작)로 서버를 켭니다.
    app.run(debug=True, port=5000)