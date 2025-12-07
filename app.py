from flask import Flask, request, jsonify  # Flask 서버 관련
import jwt            # JWT 토큰 생성 관련
import uuid           # Refresh 토큰 생성 관련
import bcrypt         # 비밀번호 암호화 관련
import datetime       # 토큰 만료 시간 설정 관련
from functools import wraps  # 데코레이터 (로그인 체크용)
import random
from flask_cors import CORS
import os

#resend 라이브러리 추가
import resend

resend.api_key = os.getenv("RESEND_API_KEY")



# --- 서버 설정 ---

# app이라는 이름의 Flask 서버를 생성
app = Flask(__name__)

# JWT 토큰을 만들 때 사용할 비밀키
app.config['SECRET_KEY'] = 'rhwkddksskrpgowntpdy' 

#CORS 설정
CORS(app)
# ---------------------------------
# OPTIONS 요청 직접 허용 
# ---------------------------------

@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = app.make_response('')
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response
# ---------------------------------
# 모든 응답에 CORS 헤더 강제 추가 ← 이것이 핵심
# ---------------------------------
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response




# (임시) 데이터베이스 대신 파이썬 딕셔너리(변수)를 사용합니다.
# (서버를 껐다 켜면 회원가입한 정보가 사라집니다.)
# [자료구조] 이메일별 인증코드 저장용 해시테이블 (빠른 조회)
users = {} 
posts = []              # 분실/습득 게시글 목록
messages = []           # 쪽지 목록
keywords = []           # 키워드 알림 목록
alerts = []             # 키워드 알림 발생 기록
email_codes = {}        # 이메일 인증코드 저장용
verified_emails = set() # 이메일 인증코드 통과확인용
refresh_tokens_db = {}  # Refresh 토큰을 저장하는 임시 DB

next_post_id = 1
next_message_id = 1
next_keyword_id = 1
next_alert_id = 1

# ------------------------------------------------------
# (추가) 실제 이메일 전송 기능 (Gmail SMTP)
# ------------------------------------------------------
def send_email(to_email, code):
    try:
        email_data = {
            "from": "CHAJABAT <onboarding@resend.dev>",
            "to": [to_email],
            "subject": "CHAJABAT 인증코드",
            "html": f"<h2>인증코드: {code}</h2>"
        }

        resend.Emails.send(email_data)
        print("메일 발송 성공!")

    except Exception as e:
        print("메일 발송 실패:", e)

# ------------------------------------------------
# 공통 유틸: 로그인된 사용자만 접근하게 하는 데코레이터
# ------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        # Authorization: Bearer <token>
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "로그인이 필요합니다.(토큰 없음)"}), 401

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "토큰이 만료되었습니다."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "유효하지 않은 토큰입니다."}), 401
        except Exception as e:
            print("JWT decode error:", e)
            return jsonify({"error": "토큰 처리 중 오류 발생"}), 401

        # email이 없으면 401
        if 'email' not in payload:
            return jsonify({"error": "토큰에 사용자 정보가 없습니다."}), 401

        # 이후 라우트에서 현재 로그인한 유저 이메일을 쓰고 싶을 때 사용
        request.user_email = payload['email']
        return f(*args, **kwargs)

    return wrapper


# ------------------------------------------------
# 0. 이메일 인증 
# ------------------------------------------------
@app.route("/api/v1/auth/send-code", methods=["POST"])
def send_code_route():
    data = request.json
    email = data.get("email")

    if not email:
        return jsonify({"error": "이메일을 입력해주세요."}), 400
    

    code = str(random.randint(100000, 999999))
    email_codes[email] = code
    
    # 이메일 실제 발송
    send_email(email, code)
    return jsonify({"message": "인증 코드가 이메일로 전송되었습니다."}), 200


# 인증코드 확인
# ------------------------------------------------------
@app.route('/api/v1/auth/verify-code', methods=['POST'])
def verify_code():
    data = request.json
    email = data.get('email')
    code = data.get('code')

    if email_codes.get(email) == code:
        del email_codes[email]
        verified_emails.add(email)
        return jsonify({"message": "이메일 인증 완료!"}), 200

    return jsonify({"error": "인증 코드가 올바르지 않습니다."}), 400

# ------------------------------------------------
# 1. 비밀번호 재설정 기능 
# ------------------------------------------------
@app.route('/api/v1/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_pw = data.get('new_password')


    if email not in users:
        return jsonify({"error": "등록되지 않은 이메일입니다."}), 404

    hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
    users[email]['password'] = hashed


    return jsonify({"message": "비밀번호가 변경되었습니다."}), 200


# ------------------------------------------------
# 2. 닉네임 중복 확인 API
# ------------------------------------------------
@app.route('/api/v1/auth/check-nickname', methods=['GET'])
def check_nickname():
    """닉네임 중복 여부 확인"""
    nickname = request.args.get('nickname')
    #[알고리즘] 선형 탐색(Linear Search): 모든 유저 순회하며 중복 닉네임 검사
    for user in users.values():
        if user['nickname'] == nickname:
            return jsonify({"available": False}), 200
    return jsonify({"available": True}), 200


# --- API 구현 ---

# 3. 회원가입 API (Notion 표의 '회원가입')
# @app.route: "이 주소('/api/v1/auth/signup')로 요청이 오면,"
# methods=['POST']: "POST 방식으로만 받겠다"는 뜻
@app.route('/api/v1/auth/signup', methods=['POST'])
def signup():
    # 프론트가 보낸 데이터를 받습니다.
    data = request.json
    email = data.get('email')
    password = data.get('password')
    nickname = data.get('nickname')
    # 기본 입력 체크
    if not all([email, password, nickname]):
        return jsonify({"error": "필수 정보를 모두 입력해주세요."}), 400


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
    

    
    # 201: Created (성공적으로 생성됨)
    return jsonify({"message": "회원가입이 성공적으로 완료되었습니다."}), 201

# 4. 로그인 API (Notion 표의 '로그인(JWT)')
@app.route('/api/v1/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # (검증 1) 가입된 유저인지 확인
    user = users.get(email)
    
    # (검증 2) 유저가 있고, 암호화된 비밀번호가 일치하는지 확인
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        
        # (토큰 생성) 로그인 성공 시, 30분 동안 유효한 JWT 토큰 생성
        access_token = jwt.encode({
            'email': email, 
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # 보안상의 이유로 30분 사용을 권장해서 30분으로 변경했습니다.
        }, app.config['SECRET_KEY'], algorithm="HS256")

        # [추가] Refresh Token 생성 (7일 유효)
        refresh_token = str(uuid.uuid4()) # DB 저장을 위해 고유한 UUID 생성
        refresh_exp = datetime.datetime.utcnow() + datetime.timedelta(days=7)
        
        # [추가] Refresh Token을 서버 DB에 저장 (이메일당 하나의 RT만 허용)
        refresh_tokens_db[email] = {
            'token': refresh_token,
            'exp': refresh_exp
        }

        # 200: OK (성공)
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'nickname': user['nickname']   # 
        }), 200
        # 401: Unauthorized (인증 실패)
    return jsonify({"error": "이메일 또는 비밀번호가 일치하지 않습니다."}), 401

# ------------------------------------------------
# 추가 - 사용자 프로필 관리
# ------------------------------------------------
# 1) 프로필 조회
@app.route('/api/v1/users/profile', methods=['GET'])
@login_required
def get_profile():
    """현재 로그인한 사용자의 프로필 정보 조회"""
    email = request.user_email
    user = users.get(email)
    
    if not user:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404
    
    return jsonify({
        "email": email,
        "nickname": user.get('nickname', ''),
        "profileImage": user.get('profileImage', '')
    }), 200

# 2) 프로필 수정
@app.route('/api/v1/users/profile', methods=['PUT'])
@login_required
def update_profile():
    """프로필 정보 수정 (닉네임, 프로필 이미지)"""
    email = request.user_email
    data = request.json
    
    if email not in users:
        return jsonify({"error": "사용자를 찾을 수 없습니다."}), 404
    
    user = users[email]
    
    # 닉네임 수정
    if 'nickname' in data:
        new_nickname = data.get('nickname')
        # 닉네임 중복 확인 (본인 제외)
        for other_email, other_user in users.items():
            if other_email != email and other_user.get('nickname') == new_nickname:
                return jsonify({"error": "이미 사용 중인 닉네임입니다."}), 400
        user['nickname'] = new_nickname
    
    # 프로필 이미지 수정
    if 'profileImage' in data:
        user['profileImage'] = data.get('profileImage')
    
    return jsonify({
        "email": email,
        "nickname": user.get('nickname', ''),
        "profileImage": user.get('profileImage', '')
    }), 200


# (추가) 토큰 재발급
@app.route('/api/v1/auth/refresh', methods=['POST'])
def refresh_token():
    data = request.json
    client_refresh_token = data.get('refresh_token')
    expired_access_token = data.get('access_token') 

    if not client_refresh_token or not expired_access_token:
        return jsonify({"error": "필수 토큰이 누락되었습니다."}), 401
    
    try:
        # 만료된 Access Token에서 email 추출
        access_payload = jwt.decode(
            expired_access_token, 
            app.config['SECRET_KEY'], 
            algorithms=["HS256"],
            # 만료/서명 검증 없이 payload만 읽어 email을 추출
            options={"verify_signature": False, "verify_exp": False} 
        )
        email = access_payload.get('email')

        # 서버 저장소의 Refresh Token 정보 가져오기
        stored_token_info = refresh_tokens_db.get(email)
        
        if not stored_token_info:
            return jsonify({"error": "유효하지 않은 Refresh Token입니다. (서버 정보 없음)"}), 401

        # UUID 일치 및 만료 시간 확인 (핵심 검증)
        is_token_match = stored_token_info['token'] == client_refresh_token
        is_not_expired = stored_token_info['exp'] > datetime.datetime.utcnow()

        if is_token_match and is_not_expired:
            
            # 새로운 Access Token 생성 (30분 유효)
            new_access_token = jwt.encode({
                'email': email, 
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) 
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            return jsonify({'access_token': new_access_token}), 200
        
        # Refresh Token 만료 처리
        if not is_not_expired:
            del refresh_tokens_db[email]
            return jsonify({"error": "Refresh Token이 만료되었습니다. 다시 로그인해주세요."}), 401
        
        # 토큰 불일치 (탈취 의심)
        if not is_token_match:
            return jsonify({"error": "토큰이 일치하지 않습니다. 비정상적인 접근입니다."}), 401

    except Exception:
        return jsonify({"error": "토큰 재발급에 실패했습니다."}), 401


    

@app.route('/api/v1/auth/logout', methods=['POST'])
@login_required
def logout():
    """ 로그아웃 (프론트에서 JWT 삭제)"""
    email = request.user_email # 데코레이터에서 가져온 이메일
    
    # 서버 저장소에서 Refresh Token 삭제 (UUID 무효화)
    if email in refresh_tokens_db:
        del refresh_tokens_db[email]

    return jsonify({"message": "로그아웃 되었습니다."}), 200

# 5. 게시판 (Post - CRUD + 상태 관리 + 검색/필터)
# ------------------------------------------------

# 1) 게시글 작성 (Create)
@app.route('/api/v1/posts', methods=['POST'])
@login_required
def create_post():
    global next_post_id, next_alert_id

    data = request.json
    post_type = data.get('type')           # 'Lost' / 'Found'
    title = data.get('title')
    content = data.get('content')
    location = data.get('location')        # 예: N4동, 도서관 등
    category = data.get('category')        # 예: 지갑, 전자기기 등
    lost_date = data.get('lost_date')      # 문자열로 받기 (YYYY-MM-DD)
    features = data.get('features')        # 특징
    images = data.get('images', [])        # 이미지 URL 리스트(임시)

    if not all([post_type, title, content, location]):
        return jsonify({"error": "type, title, content, location은 필수입니다."}), 400

    # [추가]작성자 닉네임 가져오기
    author_nickname = users.get(request.user_email, {}).get('nickname', '')
    
    post = {
        "id": next_post_id,
        "type": post_type,
        "title": title,
        "content": content,
        "location": location,
        "category": category,
        "lost_date": lost_date,
        "features": features,
        "images": images,
        "status": "Waiting",   # 기본값: 찾는 중
        "author_email": request.user_email,
        # 닉네임 저장
        "author_nickname": author_nickname,
        
        "created_at": datetime.datetime.utcnow().isoformat()
    }
    posts.append(post)
    next_post_id += 1

    #  키워드 알림 체크 (간단 버전: 제목 + 내용 문자열에 keyword 포함 여부)
    text = (title or "") + " " + (content or "")
    for kw in keywords:
        if kw["keyword"] in text:
            # 글을 작성한 본인에게는 알림 안 보낸다고 가정
            if kw["user_email"] == request.user_email:
                continue
            alerts.append({
                "id": next_alert_id,
                "user_email": kw["user_email"],
                "post_id": post["id"],
                "created_at": datetime.datetime.utcnow().isoformat(),
                "seen": False
            })
            next_alert_id += 1

    return jsonify(post), 201

# 내 게시글 목록 조회 (추가됨)
@app.route('/api/v1/posts/my', methods=['GET'])
@login_required
def get_my_posts():
    """내가 작성한 게시글 목록 조회"""
    email = request.user_email
    my_posts = [p for p in posts if p.get('author_email') == email]
    
    # [추가]닉네임 추가 (없으면 업데이트)
    for p in my_posts:
        if 'author_nickname' not in p or not p.get('author_nickname'):
            if email in users:
                p['author_nickname'] = users[email].get('nickname', '')
    
    my_posts = sorted(my_posts, key=lambda p: p['created_at'], reverse=True)
    return jsonify(my_posts), 200


# 2) 게시글 목록 조회 (검색 + 필터 + 정렬 + 간단 페이지네이션)
@app.route('/api/v1/posts', methods=['GET'])
def list_posts():
    # 쿼리 파라미터
    post_type = request.args.get('type')        # Lost / Found
    category = request.args.get('category')
    location = request.args.get('location')
    status = request.args.get('status')         # Waiting / Completed
    sort = request.args.get('sort', 'latest')   # latest / oldest
    q = request.args.get('q')                   # 키워드 검색
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 10))

    filtered = posts

    #[알고리즘] 필터링 로직 (리스트 컴프리헨션 기반, 조건문 탐색)
    # 필터 적용
    if post_type:
        filtered = [p for p in filtered if p['type'] == post_type]
    if category:
        filtered = [p for p in filtered if p.get('category') == category]
    if location:
        filtered = [p for p in filtered if p.get('location') == location]
    if status:
        filtered = [p for p in filtered if p.get('status') == status]
    if q:
        q_lower = q.lower()
        filtered = [
            p for p in filtered
            if q_lower in (p['title'] or '').lower()
            or q_lower in (p['content'] or '').lower()
        ]

    #[알고리즘] 정렬: created_at 기준으로 최신순/오래된순 정렬    
    # 정렬
    reverse = True if sort == 'latest' else False
    filtered = sorted(filtered, key=lambda p: p['created_at'], reverse=reverse)

    # [자료구조] 활용 슬라이싱(start:end)으로 부분 리스트 반환
    # 페이지네이션
    total = len(filtered)
    start = (page - 1) * size
    end = start + size
    items = filtered[start:end]

    return jsonify({
        "total": total,
        "page": page,
        "size": size,
        "items": items
    })


# 3) 게시글 상세 조회
@app.route('/api/v1/posts/<int:post_id>', methods=['GET'])
def get_post(post_id):
    for p in posts:
        if p['id'] == post_id:
            # [추가]닉네임이 없으면 최신 정보로 업데이트
            if 'author_nickname' not in p or not p.get('author_nickname'):
                author_email = p.get('author_email')
                if author_email and author_email in users:
                    p['author_nickname'] = users[author_email].get('nickname', '')
            return jsonify(p)
    return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404




# 4) 게시글 수정 (작성자만)
@app.route('/api/v1/posts/<int:post_id>', methods=['PUT'])
@login_required
def update_post(post_id):
    data = request.json
    for p in posts:
        if p['id'] == post_id:
            if p['author_email'] != request.user_email:
                return jsonify({"error": "본인이 작성한 글만 수정할 수 있습니다."}), 403

            # 수정 가능한 필드들
            p['title'] = data.get('title', p['title'])
            p['content'] = data.get('content', p['content'])
            p['location'] = data.get('location', p['location'])
            p['category'] = data.get('category', p['category'])
            p['lost_date'] = data.get('lost_date', p['lost_date'])
            p['features'] = data.get('features', p['features'])
            p['images'] = data.get('images', p['images'])

            # nickname 최신화
            email = p['author_email']
            if email in users:
                p['author_nickname'] = users[email].get('nickname', '')

            return jsonify(p)
    return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404


# 5) 게시글 삭제 (작성자만)
@app.route('/api/v1/posts/<int:post_id>', methods=['DELETE'])
@login_required
def delete_post(post_id):
    global posts
    for p in posts:
        if p['id'] == post_id:
            if p['author_email'] != request.user_email:
                return jsonify({"error": "본인이 작성한 글만 삭제할 수 있습니다."}), 403
            posts = [post for post in posts if post['id'] != post_id]
            return jsonify({"message": "삭제 완료"}), 200
    return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404


# 6) 상태 관리 (Waiting / Completed)
@app.route('/api/v1/posts/<int:post_id>/status', methods=['PATCH'])
@login_required
def update_post_status(post_id):
    data = request.json
    new_status = data.get('status')  # "Waiting" 또는 "Completed"

    if new_status not in ['Waiting', 'Completed']:
        return jsonify({"error": "status는 'Waiting' 또는 'Completed'만 가능합니다."}), 400

    for p in posts:
        if p['id'] == post_id:
            if p['author_email'] != request.user_email:
                return jsonify({"error": "본인이 작성한 글만 상태를 변경할 수 있습니다."}), 403
            p['status'] = new_status
            return jsonify(p)
    return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404

# ------------------------------------------------
# 7. 1:1 쪽지 (Direct Message)
# ------------------------------------------------

# 1) 쪽지 보내기
@app.route('/api/v1/messages', methods=['POST'])
@login_required
def send_message():
    global next_message_id

    data = request.json
    recipient_email = data.get('recipient_email')
    content = data.get('content')

    if not recipient_email or not content:
        return jsonify({"error": "recipient_email과 content는 필수입니다."}), 400

    if recipient_email not in users:
        return jsonify({"error": "존재하지 않는 사용자에게는 보낼 수 없습니다."}), 404

    msg = {
        "id": next_message_id,
        "sender_email": request.user_email,
        "recipient_email": recipient_email,
        "content": content,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "read_at": None
    }
    messages.append(msg)
    next_message_id += 1

    return jsonify(msg), 201


# 2) 받은 쪽지함
@app.route('/api/v1/messages/inbox', methods=['GET'])
@login_required
def inbox(): 
    #[알고리즘] 리스트 필터링 + 정렬
    email = request.user_email
    inbox_msgs = [m for m in messages if m['recipient_email'] == email]
    inbox_msgs = sorted(inbox_msgs, key=lambda m: m['created_at'], reverse=True)
    return jsonify(inbox_msgs)


# 3) 보낸 쪽지함
@app.route('/api/v1/messages/sent', methods=['GET'])
@login_required
def sent_box():
    email = request.user_email
    sent_msgs = [m for m in messages if m['sender_email'] == email]
    sent_msgs = sorted(sent_msgs, key=lambda m: m['created_at'], reverse=True)
    return jsonify(sent_msgs)


# 4) 쪽지 상세 조회 (+ 읽음 처리)
@app.route('/api/v1/messages/<int:message_id>', methods=['GET'])
@login_required
def message_detail(message_id):
    email = request.user_email
    for m in messages:
        if m['id'] == message_id:
            # 본인(보낸 사람 또는 받은 사람)만 조회 가능
            if email != m['sender_email'] and email != m['recipient_email']:
                return jsonify({"error": "조회 권한이 없습니다."}), 403

            # 받은 사람이 열람하면 읽음 처리
            if email == m['recipient_email'] and m['read_at'] is None:
                m['read_at'] = datetime.datetime.utcnow().isoformat()

            return jsonify(m)
    return jsonify({"error": "쪽지를 찾을 수 없습니다."}), 404


# ------------------------------------------------
# 8. 키워드 알림 (Keyword Alert)
# ------------------------------------------------

# 1) 키워드 등록
@app.route('/api/v1/keywords', methods=['POST'])
@login_required
def add_keyword():
    global next_keyword_id
    data = request.json
    keyword = data.get('keyword')

    if not keyword:
        return jsonify({"error": "keyword는 필수입니다."}), 400

    kw = {
        "id": next_keyword_id,
        "user_email": request.user_email,
        "keyword": keyword
    }
    keywords.append(kw)
    next_keyword_id += 1

    return jsonify(kw), 201


# 2) 내 키워드 목록 조회
@app.route('/api/v1/keywords', methods=['GET'])
@login_required
def list_keywords():
    email = request.user_email
    my_keywords = [k for k in keywords if k['user_email'] == email]
    return jsonify(my_keywords)


# 3) 키워드 삭제
@app.route('/api/v1/keywords/<int:keyword_id>', methods=['DELETE'])
@login_required
def delete_keyword(keyword_id):
    global keywords
    email = request.user_email

    for k in keywords:
        if k['id'] == keyword_id:
            if k['user_email'] != email:
                return jsonify({"error": "본인의 키워드만 삭제할 수 있습니다."}), 403
            keywords = [kw for kw in keywords if kw['id'] != keyword_id]
            return jsonify({"message": "키워드 삭제 완료"}), 200

    return jsonify({"error": "키워드를 찾을 수 없습니다."}), 404


# --- 서버 실행 ---

# 이 app.py 파일을 직접 실행했을 때(예: 'python app.py') 
# 아래 코드를 실행하라는 의미입니다.
if __name__ == '__main__':
    # 5000번 포트로, 디버그 모드(코드 수정 시 자동 재시작)로 서버를 켭니다.
    app.run(debug=True, port=5000)
