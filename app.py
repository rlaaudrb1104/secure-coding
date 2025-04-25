import eventlet

eventlet.monkey_patch()

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
)
import MySQLdb
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, join_room, emit
import os, bcrypt, json
from dotenv import load_dotenv
import uuid
from datetime import datetime
from decimal import Decimal

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from markupsafe import escape
import time

# 환경 변수 로드
load_dotenv()

# Flask 앱 설정
app = Flask(__name__)

csrf = CSRFProtect(app)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per second"],  # 예시
)

# Flask 앱과 연결
limiter.init_app(app)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "changeme"),
    MYSQL_HOST=os.getenv("MYSQL_HOST", "db"),
    MYSQL_USER=os.getenv("MYSQL_USER", "trading_user"),
    MYSQL_PASSWORD=os.getenv("MYSQL_PASSWORD", "example"),
    MYSQL_DB=os.getenv("MYSQL_DATABASE", "trading"),
    
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # HTTPS 환경일 때만 작동함
    SESSION_COOKIE_SAMESITE='Lax',    # 또는 'Strict'
    
    UPLOAD_FOLDER="static/uploads",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # 5MB
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# 서비스 초기화
mysql = MySQL(app)
socketio = SocketIO(
    app,
    async_mode="eventlet",
    cors_allowed_origins="*",
    manage_session=False,
    message_queue="redis://redis:6379",
)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;"
    )
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------
# 회원가입 / 로그인 / 로그아웃
# ------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        if not username or not email or len(password) < 8:
            flash("입력값을 확인하세요.", "error")
            return render_template("register.html")
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email)
        )
        if cur.fetchone():
            cur.close()
            flash("이미 사용 중인 계정입니다.", "error")
            return render_template("register.html")
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cur.execute(
            "INSERT INTO users(username,email,password_hash) VALUES(%s,%s,%s)",
            (username, email, pw_hash),
        )
        mysql.connection.commit()
        cur.close()
        flash("가입 완료", "success")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id,password_hash,is_blocked,is_admin FROM users WHERE email=%s",
            (email,),
        )
        row = cur.fetchone()
        cur.close()
        if not row or row[2]:
            flash("로그인 불가", "error")
            return render_template("login.html")
        user_id, pw_hash, _, is_admin = row
        if bcrypt.checkpw(password.encode(), pw_hash.encode()):
            session.clear()
            session["user_id"] = user_id
            session["is_admin"] = bool(is_admin)
            flash("로그인 성공", "success")
            return redirect(url_for("index"))
        flash("인증 실패", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃", "info")
    return redirect(url_for("index"))


# ------------------------
# 메인 & 상품 상세
# ------------------------
@app.route("/")
def index():
    # 검색 파라미터
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    price_min = request.args.get("price_min", "").strip()
    price_max = request.args.get("price_max", "").strip()
    sort = request.args.get("sort", "created_at")

    cur = mysql.connection.cursor()
    # 인기 상품 (조회수 상위 8, 판매자명 포함)
    cur.execute(
        """
        SELECT p.id, p.title, p.description, p.price, p.image_paths, p.views, u.username
          FROM products p JOIN users u ON p.seller_id=u.id
         WHERE p.status='available'
         ORDER BY p.views DESC
         LIMIT 8
    """
    )
    popular = cur.fetchall()

    # 전체 상품 (검색 & 필터 + 판매자명)
    sql = """
        SELECT p.id, p.title, p.description, p.price, p.image_paths, p.views, u.username
          FROM products p JOIN users u ON p.seller_id=u.id
         WHERE p.status='available'
    """
    params = []
    if q:
        sql += " AND MATCH(p.title,p.description) AGAINST(%s IN NATURAL LANGUAGE MODE)"
        params.append(q)
    if category:
        sql += " AND p.category=%s"
        params.append(category)
    if price_min:
        sql += " AND p.price>=%s"
        params.append(price_min)
    if price_max:
        sql += " AND p.price<=%s"
        params.append(price_max)
    sql += f" ORDER BY p.{sort if sort in ('price','created_at','views') else 'created_at'} DESC"
    cur.execute(sql, tuple(params))
    all_p = cur.fetchall()
    cur.close()

    def parse(rows):
        out = []
        for r in rows:
            raw = json.loads(r[4]) if r[4] else []
            # rel paths
            rel = [p[len("static/") :] if p.startswith("static/") else p for p in raw]
            out.append(
                {
                    "id": r[0],
                    "title": r[1],
                    "description": r[2],
                    "price": float(r[3]),
                    "image_paths": rel,
                    "views": r[5],
                    "seller_name": r[6],
                }
            )
        return out

    return render_template(
        "index.html", popular_products=parse(popular), all_products=parse(all_p)
    )


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    me = session["user_id"]
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT
            p.id,
            p.title,
            p.description,
            p.price,
            p.image_paths,
            p.views,
            u.id          AS seller_id,
            u.username    AS seller_name
        FROM products p
        JOIN users u ON p.seller_id = u.id
        WHERE p.id = %s
    """,
        (product_id,),
    )
    row = cur.fetchone()
    cur.close()

    if not row:
        flash("상품을 찾을 수 없습니다.", "error")
        return redirect(url_for("index"))

    # JSON 문자열 → Python 리스트
    raw_paths = json.loads(row[4]) if row[4] else []
    # "static/uploads/xxx.jpg" → "uploads/xxx.jpg"
    rel_paths = [
        p[len("static/") :] if p.startswith("static/") else p for p in raw_paths
    ]

    product = {
        "id": row[0],
        "title": row[1],
        "description": row[2],
        "price": float(row[3]),
        "image_paths": rel_paths,
        "views": row[5],
        "seller_id": row[6],
        "seller_name": row[7],
    }

    room = f"{min(me, product['seller_id'])}_{max(me, product['seller_id'])}"

    # 내가 올린 글인지 플래그
    is_owner = me == product["seller_id"]

    return render_template(
        "product_detail.html", product=product, room=room, is_owner=is_owner
    )


# ------------------------
# 상품 등록
# ------------------------
@app.route("/product/new", methods=["GET", "POST"])
def new_product():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"].strip()
        desc = request.form["description"].strip()
        price = request.form["price"].strip()

        # 1) 필수 입력 & 숫자 검증
        if not title or not desc or not price:
            flash("모든 필드를 입력하세요.", "error")
            return render_template("new_product.html")
        try:
            price_val = float(price)
            assert price_val >= 0
        except:
            flash("가격을 올바르게 입력하세요.", "error")
            return render_template("new_product.html")

        # 2) 업로드 폴더 준비
        upload_dir = app.config["UPLOAD_FOLDER"]
        os.makedirs(upload_dir, exist_ok=True)

        # 3) 파일 저장 & 경로 수집
        images = []
        for f in request.files.getlist("images"):
            if f and allowed_file(f.filename):
                unique_name = f"{uuid.uuid4().hex}_{secure_filename(f.filename)}"
                abs_path = os.path.join(upload_dir, unique_name)
                f.save(abs_path)
                # DB엔 상대 경로만 저장
                images.append(os.path.join("uploads", unique_name))

        # 4) DB 삽입
        cur = mysql.connection.cursor()
        try:
            cur.execute(
                "INSERT INTO products(seller_id,title,description,price,image_paths) "
                "VALUES(%s,%s,%s,%s,%s)",
                (session["user_id"], title, desc, price_val, json.dumps(images)),
            )
            mysql.connection.commit()
            flash("상품이 성공적으로 등록되었습니다.", "success")
            return redirect(url_for("index"))
        except Exception:
            mysql.connection.rollback()
            flash("상품 등록 중 오류가 발생했습니다.", "error")
        finally:
            cur.close()

    return render_template("new_product.html")


# ------------------------
# 1:1 사용자 채팅 목록
# ------------------------
@app.route("/chats")
def chat_list():
    if "user_id" not in session:
        return redirect(url_for("login"))

    me = session["user_id"]
    cur = mysql.connection.cursor()
    # ——— 0) 전체 채팅방을 제일 위에 삽입 ———
    conversations = [
        {
            "room": f"All",
            "other_name": "전체 채팅방",
            "last_msg": "모든 사용자가 참여할 수 있는 채팅방입니다.",
            "last_time": "",
        }
    ]
    # 내 채팅방만 검색
    cur.execute(
        """
        SELECT DISTINCT room 
        FROM messages 
        WHERE room LIKE %s OR room LIKE %s
    """,
        (f"{me}_%", f"%_{me}"),
    )

    rooms = [r[0] for r in cur.fetchall()]
    conversations = []

    for room_db in rooms:
        parts = room_db.split("_")
        if len(parts) != 2:
            continue
        try:
            u1, u2 = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if me not in (u1, u2):
            continue
        other = u2 if u1 == me else u1

        # 최근 메시지
        cur.execute(
            """
            SELECT sender_id, content, DATE_FORMAT(sent_at, '%%p %%l:%%i')
            FROM messages
            WHERE room = %s
            ORDER BY sent_at DESC
            LIMIT 1
        """,
            (room_db,),
        )
        last = cur.fetchone()
        if not last:
            continue
        sender_id, content, ts = last

        # 상대 이름
        cur.execute("SELECT username FROM users WHERE id=%s", (other,))
        other_name = cur.fetchone()[0]

        conversations.append(
            {
                "room": room_db,
                "other_id": other,
                "other_name": other_name,
                "last_msg": content,
                "last_time": ts,
            }
        )
    cur.close()
    fixed, rest = conversations[:1], conversations[1:]
    rest.sort(key=lambda x: x["last_time"], reverse=True)
    conversations = fixed + rest

    return render_template("chat_list.html", chats=conversations)


# ------------------------
# 1:1 채팅 화면
# ------------------------
@app.route("/chat/<room>")
def chat(room):
    if "user_id" not in session:
        return redirect(url_for("login"))

    me = session["user_id"]
    # — 전체 채팅방 —
    if room == "All":
        other_name = "전체 채팅방"
        cur = mysql.connection.cursor()
        cur.execute(
            """
            SELECT sender_id, content,
                   DATE_FORMAT(sent_at,'%%p %%l:%%i') AS time
              FROM messages
             WHERE room=%s
             ORDER BY id ASC
        """,
            (room,),
        )
        history = [{"sender": r[0], "msg": r[1], "time": r[2]} for r in cur.fetchall()]
        cur.close()
        return render_template(
            "chat.html", room=room, other_name=other_name, history=history
        )
    # 1) 토큰 파싱
    try:
        a, b = room.split("_")
        u1, u2 = int(a), int(b)
    except ValueError:
        abort(404)

    # 2) 나도 방 당사자인지 검사
    if me not in (u1, u2):
        abort(403)

    # 3) canonical token (“작은ID_큰ID”) 생성
    small, large = sorted([u1, u2])
    canonical = f"{small}_{large}"

    # 4) canonical 과 다르면 바로 리디렉트
    if room != canonical:
        return redirect(url_for("chat", room=canonical))

    # 이제 room = canonical 으로 안전하게 사용
    room = canonical
    # 상대방 ID
    other = u2 if me == u1 else u1

    # 상대방 이름 조회
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM users WHERE id=%s", (other,))
    other_name = cur.fetchone()[0]
    # 메시지 내역 로드
    cur.execute(
        """
        SELECT sender_id, content,
            DATE_FORMAT(sent_at, '%%p %%l:%%i') AS time
            FROM messages
            WHERE room=%s
        ORDER BY id ASC
    """,
        (room,),
    )
    history = [{"sender": r[0], "msg": r[1], "time": r[2]} for r in cur.fetchall()]
    cur.close()

    return render_template(
        "chat.html", room=room, other_name=other_name, history=history
    )


@socketio.on("join")
def on_join(data):
    join_room(data["room"])
    # (원하면) 입장 메시지
    emit(
        "status",
        {"msg": f"{session['user_id']}님이 채팅에 참여했습니다."},
        room=data["room"],
    )


# 전역 딕셔너리: 최근 사용자별 메시지 전송 시각 저장 (Rate Limit용)
user_last_send = {}  # {user_id: timestamp}

@socketio.on("message")
def on_message(data):
    room_db = data.get("room")
    msg = data.get("msg")
    sender = session.get("user_id")

    # 1. 세션/데이터 유효성 체크
    if not sender or not room_db or not msg:
        emit("error", {"msg": "잘못된 요청입니다."}, room=request.sid)
        return

    # 2. 메시지 형식 및 길이 검증 (메시지 검증)
    if not isinstance(msg, str) or not (1 <= len(msg) <= 500):
        emit("error", {"msg": "메시지는 1~500자 사이여야 합니다."}, room=request.sid)
        return

    # 3. Rate Limiting (1초에 1회 이하)
    now = time.time()
    last = user_last_send.get(sender, 0)
    if now - last < 1.0:
        emit("error", {"msg": "너무 빠르게 메시지를 전송하고 있습니다."}, room=request.sid)
        return
    user_last_send[sender] = now

    # 4. 메시지 escape 처리 (XSS 방지)
    msg_clean = escape(msg)

    # 5. DB 저장
    cur = mysql.connection.cursor()
    cur.execute(
        """
        INSERT INTO messages (room, sender_id, content, sent_at)
        VALUES (%s, %s, %s, NOW())
        """,
        (room_db, sender, msg_clean),
    )
    mysql.connection.commit()
    cur.close()

    # 6. 클라이언트로 브로드캐스트
    emit(
        "message",
        {"sender": sender, "msg": msg_clean, "time": data.get("time", "")},
        room=room_db,
    )

@app.route("/find_friends")
def find_friends():
    if "user_id" not in session:
        return redirect(url_for("login"))
    me = session["user_id"]

    # 검색어
    fq = request.args.get("q", "").strip()

    cur = mysql.connection.cursor()
    if fq:
        # 이름에 검색어가 포함된 사용자, 본인 제외
        cur.execute(
            """
            SELECT id, username
              FROM users
             WHERE username LIKE %s
               AND id != %s
             ORDER BY username
        """,
            (f"%{fq}%", me),
        )
    else:
        # 전체 사용자, 본인 제외
        cur.execute(
            """
            SELECT id, username
              FROM users
             WHERE id != %s
             ORDER BY username
        """,
            (me,),
        )
    rows = cur.fetchall()
    cur.close()

    # 각 row → dict로 변환, 대화방 토큰 생성
    friends = []
    for uid, uname in rows:
        small, large = sorted([me, uid])
        room = f"{small}_{large}"
        friends.append({"id": uid, "username": uname, "room": room})

    return render_template("find_friends.html", friends=friends, fq=fq)

@app.route('/mypage', methods=['GET', 'POST'])
def mypage():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']

    # ------------------------------------------------
    # 1) POST로 비밀번호 확인 요청 처리
    # ------------------------------------------------
    if request.method == 'POST' and 'current_password' in request.form:
        pwd = request.form['current_password']

        # DB에서 기존 해시 읽기
        cur = mysql.connection.cursor()
        cur.execute("SELECT password_hash FROM users WHERE id=%s", (me,))
        row = cur.fetchone()
        cur.close()

        stored_hash = row[0] if row else None
        verified = False

        if stored_hash:
            try:
                # bcrypt.checkpw(평문, 해시) -> bool
                verified = bcrypt.checkpw(
                    pwd.encode('utf-8'),
                    stored_hash.encode('utf-8')
                )
            except ValueError:
                verified = False

        if verified:
            session['password_verified'] = True
        else:
            flash('비밀번호가 일치하지 않습니다.', 'error')

        return redirect(url_for('mypage'))

    # ------------------------------------------------
    # 2) 비밀번호 확인 여부
    # ------------------------------------------------
    password_verified = session.get('password_verified', False)

    # ------------------------------------------------
    # 3) 비밀번호가 확인된 후 프로필 수정 or 비밀번호 변경 처리
    #    (예시: 새로운 비밀번호 설정)
    # ------------------------------------------------
    if request.method == 'POST' and password_verified:
        # profile 수정 예: 소개글 변경
        new_intro = request.form.get('intro','').strip()
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET intro=%s WHERE id=%s",
                    (new_intro, me))
        mysql.connection.commit()

        # password 변경 예
        new_pwd = request.form.get('new_password', '').strip()
        if new_pwd:
            # bcrypt 해시 생성
            pw_hash = bcrypt.hashpw(
                new_pwd.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                        (pw_hash, me))
            mysql.connection.commit()

        cur.close()
        flash('프로필이 업데이트되었습니다.', 'success')
        # 비밀번호 재확인 상태 해제
        session.pop('password_verified', None)
        return redirect(url_for('mypage'))

    # ------------------------------------------------
    # 4) GET 요청: 소개글 불러오기
    # ------------------------------------------------
    cur = mysql.connection.cursor()
    cur.execute("SELECT intro FROM users WHERE id=%s", (me,))
    row = cur.fetchone()
    cur.close()

    intro = row[0].strip() if row and row[0] and row[0].strip() else '소개글을 작성해보세요'

    return render_template('mypage.html',
                           password_verified=password_verified,
                           user={'intro': intro})

@app.route('/update_profile', methods=['POST'])
def update_profile():
    # 1) 로그인 체크
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']

    # 2) 비밀번호 확인 여부 확인
    if not session.get('password_verified'):
        flash('프로필을 변경하려면 먼저 비밀번호를 확인해주세요.', 'error')
        return redirect(url_for('mypage'))

    # 3) 폼에서 받은 새로운 소개글 처리
    new_intro = request.form.get('intro', '').strip()

    # 4) DB 업데이트
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE users SET intro = %s WHERE id = %s",
        (new_intro, me)
    )
    mysql.connection.commit()
    cur.close()

    # 5) 완료 메시지, 비밀번호 확인 세션 초기화, 마이페이지로 리다이렉트
    flash('소개글이 성공적으로 변경되었습니다.', 'success')
    session.pop('password_verified', None)
    return redirect(url_for('mypage'))

@app.route('/change_password', methods=['POST'])
def change_password():
    # 1) 로그인 체크
    if 'user_id' not in session:
        return redirect(url_for('login'))
    me = session['user_id']

    # 2) 비밀번호 확인 상태 확인
    if not session.get('password_verified'):
        flash('비밀번호를 변경하려면 먼저 현재 비밀번호를 확인해주세요.', 'error')
        return redirect(url_for('mypage'))

    # 3) 폼 데이터 읽기
    new_pwd = request.form.get('new_password', '').strip()
    confirm = request.form.get('new_password_confirm', '').strip()

    # 4) 유효성 검사
    if not new_pwd or not confirm:
        flash('비밀번호와 확인 항목을 모두 입력해주세요.', 'error')
        return redirect(url_for('mypage'))
    if new_pwd != confirm:
        flash('새 비밀번호 확인이 일치하지 않습니다.', 'error')
        return redirect(url_for('mypage'))
    if len(new_pwd) < 6:
        flash('새 비밀번호는 최소 6자 이상이어야 합니다.', 'error')
        return redirect(url_for('mypage'))

    # 5) 해시 생성
    hashed = bcrypt.hashpw(new_pwd.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # 6) DB 업데이트
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (hashed, me)
    )
    mysql.connection.commit()
    cur.close()

    # 7) 완료 처리
    flash('비밀번호가 성공적으로 변경되었습니다.', 'success')
    # 다시 비밀번호 확인 상태는 초기화
    session.pop('password_verified', None)
    return redirect(url_for('mypage'))

# ------------------------
# 신고 & 차단
# ------------------------
@app.route("/report/product/<int:product_id>", methods=["POST"])
def report_product(product_id):
    
    if "user_id" not in session:
        flash("신고하려면 로그인해야 합니다.", "error")
        return redirect(url_for("login"))

    reporter = session["user_id"]
    reason = request.form.get("reason", "").strip()

    cur = mysql.connection.cursor()

    # 🔍 이미 신고했는지 확인
    cur.execute(
        """
        SELECT id FROM reports
         WHERE reporter_id = %s AND target_type = 'product' AND target_id = %s
    """,
        (reporter, product_id),
    )
    existing = cur.fetchone()

    if existing:
        flash("이미 이 상품을 신고하셨습니다.", "info")
    else:
        # 🚨 새 신고 등록
        cur.execute(
            """
            INSERT INTO reports
                (reporter_id, target_type, target_id, reason, created_at)
            VALUES
                (%s, 'product', %s, %s, NOW())
        """,
            (reporter, product_id, reason),
        )
        mysql.connection.commit()
        flash("해당 상품이 신고되었습니다.", "success")

    cur.close()
    return redirect(url_for("product_detail", product_id=product_id))


@app.route("/product/<int:product_id>/edit", methods=["GET", "POST"])
def edit_product(product_id):
    # 로그인 여부
    if "user_id" not in session:
        return redirect(url_for("login"))

    me = session["user_id"]
    cur = mysql.connection.cursor()
    # 상품 조회
    cur.execute(
        """
        SELECT seller_id, title, description, price
          FROM products
         WHERE id=%s
    """,
        (product_id,),
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        flash("상품을 찾을 수 없습니다.", "error")
        return redirect(url_for("index"))

    seller_id, title, description, price = row
    # 본인 소유인지 체크
    if seller_id != me:
        cur.close()
        abort(403)

    if request.method == "POST":
        # 폼에서 받은 값
        new_title = request.form.get("title", "").strip()
        new_description = request.form.get("description", "").strip()
        try:
            new_price = float(request.form.get("price", price))
        except ValueError:
            new_price = price

        # 유효성 간단 체크
        if not new_title:
            flash("제목을 입력해주세요.", "error")
        else:
            cur.execute(
                """
                UPDATE products
                   SET title=%s,
                       description=%s,
                       price=%s
                 WHERE id=%s
            """,
                (new_title, new_description, new_price, product_id),
            )
            mysql.connection.commit()
            cur.close()
            flash("상품이 수정되었습니다.", "success")
            return redirect(url_for("product_detail", product_id=product_id))

    else:
        # GET: 기존 값을 폼에 채워 넣기
        new_title = title
        new_description = description
        new_price = price
    cur.close()

    return render_template(
        "edit_product.html",
        product_id=product_id,
        title=new_title,
        description=new_description,
        price=new_price,
    )


@app.route("/product/<int:product_id>/delete", methods=["POST"])
def delete_product(product_id):
    # 로그인 검사
    if "user_id" not in session:
        return redirect(url_for("login"))

    me = session["user_id"]
    cur = mysql.connection.cursor()

    # 상품의 소유자 확인
    cur.execute(
        "SELECT seller_id, image_paths FROM products WHERE id=%s", (product_id,)
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        flash("해당 상품이 없습니다.", "error")
        return redirect(url_for("index"))

    seller_id, image_paths_json = row
    if seller_id != me:
        cur.close()
        abort(403)

    # DB에서 상품 삭제
    cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
    mysql.connection.commit()
    cur.close()

    flash("상품이 삭제되었습니다.", "success")
    return redirect(url_for("index"))


# ------------------------
# 송금 & 거래 내역
# ------------------------
@app.route("/transaction/new", methods=["GET", "POST"])
def new_transaction():
    if "user_id" not in session:
        return redirect(url_for("login"))
    me = session["user_id"]

    # (1) DictCursor 로 딕셔너리 형태로 받기
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # (2) 내 잔액 조회
    cur.execute("SELECT balance FROM users WHERE id=%s", (me,))
    row = cur.fetchone()
    balance = row["balance"] if row else Decimal("0")

    # (3) GET 파라미터에서 product_id 로 수신자/금액 셋업
    product_id   = request.args.get("product_id", type=int)
    to_user_id   = None
    to_user_name = ""
    amount       = Decimal("0")

    if product_id:
        cur.execute(
            "SELECT seller_id, price FROM products WHERE id=%s",
            (product_id,)
        )
        prod = cur.fetchone()
        if prod:
            to_user_id = prod["seller_id"]
            amount     = Decimal(prod["price"])
            # 수신자 이름 조회
            cur.execute(
                "SELECT username FROM users WHERE id=%s",
                (to_user_id,)
            )
            u = cur.fetchone()
            to_user_name = u["username"] if u else ""

    # (4) POST 요청 처리: 송금 로직
    if request.method == "POST":
        to_user_id = request.form.get("to_user_id", type=int)
        amount     = Decimal(request.form.get("amount","0"))

        # 검증
        if to_user_id == me:
            flash("자기 자신에게는 송금할 수 없습니다.", "error")
            return redirect(request.url)
        if amount <= 0:
            flash("송금 금액이 올바르지 않습니다.", "error")
            return redirect(request.url)
        if amount > balance:
            flash("잔액이 부족합니다.", "error")
            return redirect(request.url)

        try:
            cur.execute("START TRANSACTION")

            # 내 계좌 차감
            cur.execute("""
                UPDATE users
                   SET balance = balance - %s
                 WHERE id = %s AND balance >= %s
            """, (amount, me, amount))
            if cur.rowcount == 0:
                raise Exception("잔액 부족 또는 사용자 오류")

            # 상대방 계좌 입금
            cur.execute("""
                UPDATE users
                   SET balance = balance + %s
                 WHERE id = %s
            """, (amount, to_user_id))

            # 거래내역 기록
            cur.execute("""
                INSERT INTO transactions
                    (from_user_id, to_user_id, amount, status, created_at)
                VALUES (%s, %s, %s, 'completed', NOW())
            """, (me, to_user_id, amount))

            mysql.connection.commit()
            flash(f"{amount:,}원 송금이 완료되었습니다.", "success")
            return redirect(url_for("index"))

        except Exception as e:
            mysql.connection.rollback()
            flash("송금 중 오류가 발생했습니다: " + str(e), "error")
            return redirect(request.url)

        finally:
            cur.close()

    # (5) GET 일 때 템플릿 렌더
    cur.close()
    return render_template(
        "new_transaction.html",
        to_user_id=to_user_id,
        to_user_name=to_user_name,
        amount=amount,
        balance=balance,
    )

# @app.route("/transactions")
# def transactions():
#     if "user_id" not in session:
#         return redirect(url_for("login"))
#     uid = session["user_id"]
#     cur = mysql.connection.cursor()
#     cur.execute(
#         """SELECT id,to_user_id,amount,status,created_at
#                    FROM transactions
#                   WHERE from_user_id=%s OR to_user_id=%s
#                ORDER BY created_at DESC""",
#         (uid, uid),
#     )
#     txs = cur.fetchall()
#     cur.close()
#     return render_template("transactions.html", transactions=txs)


# ------------------------
# 관리자 대시보드 및 관리
# ------------------------
@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    cur = mysql.connection.cursor()
    cur.execute("SELECT DATE(created_at),COUNT(*) FROM users GROUP BY DATE(created_at)")
    us = cur.fetchall()
    cur.execute(
        """SELECT DATE(created_at),SUM(amount)
                   FROM transactions WHERE status='completed'
                   GROUP BY DATE(created_at)"""
    )
    ss = cur.fetchall()
    cur.execute(
        "SELECT DATE(created_at),COUNT(*) FROM reports GROUP BY DATE(created_at)"
    )
    rs = cur.fetchall()
    cur.close()
    return render_template(
        "admin/dashboard.html", user_stats=us, sales_stats=ss, report_stats=rs
    )


@app.route("/admin/products")
def admin_products():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    cur = mysql.connection.cursor()
    cur.execute(
        """SELECT p.id, p.title, u.username AS seller_name, p.price, p.status, p.created_at
               FROM products p
               JOIN users u ON p.seller_id = u.id
               ORDER BY p.created_at DESC"""
    )
    ps = cur.fetchall()
    cur.close()
    return render_template("admin/products.html", products=ps)


@app.route("/admin/product/delete", methods=["POST"])
def admin_delete_product():
    if not session.get("is_admin"):
        return redirect(url_for("admin_products"))
    pid = request.form["product_id"]
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM products WHERE id=%s", (pid,))
    mysql.connection.commit()
    cur.close()
    flash("삭제됨", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/product/block", methods=["POST"])
def admin_block_product():
    if not session.get("is_admin"):
        return redirect(url_for("admin_products"))
    pid = request.form["product_id"]
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET status='blocked' WHERE id=%s", (pid,))
    mysql.connection.commit()
    cur.close()
    flash("차단됨", "success")
    return redirect(url_for("admin_products"))


@app.route("/admin/reports")
def admin_reports():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT r.id,
               ru.username AS reporter_name,
               r.target_type,
               r.target_id,
               r.reason,
               r.created_at,
               CASE
                   WHEN r.target_type = 'user' THEN (
                       SELECT username FROM users WHERE id = r.target_id
                   )
                   WHEN r.target_type = 'product' THEN (
                       SELECT title FROM products WHERE id = r.target_id
                   )
                   ELSE NULL
               END AS target_name
        FROM reports r
        JOIN users ru ON r.reporter_id = ru.id
        ORDER BY r.created_at DESC
        """
    )
    rs = cur.fetchall()
    cur.close()
    return render_template("admin/reports.html", reports=rs)


@app.route("/admin/transactions")
def admin_transactions():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    cur = mysql.connection.cursor()
    cur.execute(
        """SELECT id,from_user_id,to_user_id,amount,status,created_at
                   FROM transactions ORDER BY created_at DESC"""
    )
    tx = cur.fetchall()
    cur.close()
    return render_template("admin/transactions.html", transactions=tx)


@app.route("/admin/block", methods=["POST"])
def block_target():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    t = request.form
    tt = t["target_type"]
    tid = t["target_id"]
    reason = t["reason"].strip()
    cur = mysql.connection.cursor()
    cur.execute(
        """INSERT INTO blocks
                   (target_type,target_id,blocked_by,reason)
                   VALUES(%s,%s,%s,%s)""",
        (tt, tid, session["user_id"], reason),
    )
    if tt == "user":
        cur.execute("UPDATE users SET is_blocked=TRUE WHERE id=%s", (tid,))
    else:
        cur.execute("UPDATE products SET status='blocked' WHERE id=%s", (tid,))
    mysql.connection.commit()
    cur.close()
    flash("차단 완료", "success")
    return redirect(url_for("admin_dashboard"))

# 관리자용 사용자 관리 목록
@app.route("/admin/users")
def admin_users():
    # 관리자 권한 체크
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    # DictCursor 로 dict 형태로 받아옴
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT
            id,
            username,
            email,
            is_blocked,
            DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i') AS created_at
          FROM users
         ORDER BY created_at DESC
    """)
    users = cur.fetchall()
    cur.close()

    return render_template("admin/users.html", users=users)

# 관리자용 사용자 삭제
@app.route("/admin/user/delete", methods=["POST"])
def admin_delete_user():
    if not session.get("is_admin"):
        return redirect(url_for("admin_users"))

    uid = request.form["user_id"]
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    mysql.connection.commit()
    cur.close()

    flash("사용자가 삭제되었습니다.", "success")
    return redirect(url_for("admin_users"))

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000,)
