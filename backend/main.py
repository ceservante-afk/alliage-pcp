from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import json, os, hashlib, hmac, base64
import urllib.parse
import sqlite3

SECRET_KEY = os.environ.get("SECRET_KEY", "alliage2026pcp")
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

DATABASE_URL = os.environ.get("DATABASE_URL", "")

ROLE_SETORES = {
    "pcp_metal": ["SOLDA ELÉTRICA", "ESTAMPARIA", "USINAGEM", "MICRO/USINAGEM"],
    "pcp_acab":  ["PINTURA", "GALVANOPLASTIA"],
    "admin":     None,
    "fabricacao": None,
    "visitante":  None,
}

ROLE_PREFIXOS = {
    "pcp_metal": ["ESTA", "USIN", "MUSI"],
    "pcp_acab":  ["PINP", "PINL", "GALV"],
    "admin":     None,
}

app = FastAPI(title="Alliage PCP", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

def hash_password(p):
    s = os.urandom(16)
    k = hashlib.pbkdf2_hmac("sha256", p.encode(), s, 100000)
    return base64.b64encode(s+k).decode()

def verify_password(p, stored):
    try:
        d = base64.b64decode(stored.encode())
        s,k = d[:16],d[16:]
        return hmac.compare_digest(k, hashlib.pbkdf2_hmac("sha256",p.encode(),s,100000))
    except: return False

# Usar pg8000 (pure Python, compatível com qualquer versão)
USE_PG = bool(DATABASE_URL)

def get_conn():
    if USE_PG:
        import pg8000.native
        u = urllib.parse.urlparse(DATABASE_URL)
        return pg8000.native.Connection(
            host=u.hostname, port=u.port or 5432,
            database=u.path.lstrip('/'),
            user=u.username, password=u.password,
            ssl_context=True
        )
    else:
        conn = sqlite3.connect("/tmp/pcp.db")
        conn.row_factory = sqlite3.Row
        return conn

def db_exec(conn, sql, params=()):
    if USE_PG:
        sql_pg = sql.replace("?", "%s").replace("INTEGER PRIMARY KEY AUTOINCREMENT","SERIAL PRIMARY KEY").replace("datetime('now')","NOW()::text").replace("DISTINCT ON (grupo)","DISTINCT ON (grupo)")
        return conn.run(sql_pg, list(params))
    else:
        return conn.execute(sql, params)

def db_fetchone(conn, sql, params=()):
    if USE_PG:
        import pg8000.native
        sql_pg = sql.replace("?","%s")
        rows = conn.run(sql_pg, list(params))
        if rows:
            cols = [c['name'] for c in conn.columns]
            return dict(zip(cols, rows[0]))
        return None
    else:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None

def db_fetchall(conn, sql, params=()):
    if USE_PG:
        sql_pg = sql.replace("?","%s")
        rows = conn.run(sql_pg, list(params))
        cols = [c['name'] for c in conn.columns]
        return [dict(zip(cols,r)) for r in rows]
    else:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]

def get_db():
    conn = get_conn()
    try: yield conn
    finally:
        if USE_PG: conn.close()
        else: conn.close()

def init_db():
    conn = get_conn()
    if USE_PG:
        tables = [
            """CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, full_name TEXT,
                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'fabricacao',
                active INTEGER DEFAULT 1, created_at TEXT DEFAULT (NOW()::text))""",
            """CREATE TABLE IF NOT EXISTS prog_data (
                id SERIAL PRIMARY KEY, data_json TEXT NOT NULL, uploaded_by TEXT,
                uploaded_at TEXT DEFAULT (NOW()::text), description TEXT, semana TEXT, grupo TEXT)""",
            """CREATE TABLE IF NOT EXISTS prog_config (
                id SERIAL PRIMARY KEY, config_json TEXT NOT NULL, updated_by TEXT,
                updated_at TEXT DEFAULT (NOW()::text))""",
            """CREATE TABLE IF NOT EXISTS roteiro_data (
                id SERIAL PRIMARY KEY, data_json TEXT NOT NULL, uploaded_by TEXT,
                uploaded_at TEXT DEFAULT (NOW()::text))""",
            """CREATE TABLE IF NOT EXISTS galva_map (
                id SERIAL PRIMARY KEY, map_json TEXT NOT NULL, uploaded_by TEXT,
                uploaded_at TEXT DEFAULT (NOW()::text))""",
            """CREATE TABLE IF NOT EXISTS edit_log (
                id SERIAL PRIMARY KEY, username TEXT, action TEXT, detail TEXT,
                ts TEXT DEFAULT (NOW()::text))""",
        ]
        for t in tables:
            conn.run(t)
        rows = conn.run("SELECT id FROM users WHERE username='admin'")
        if not rows:
            conn.run("INSERT INTO users (username,full_name,password_hash,role) VALUES (%s,%s,%s,%s)",
                     ["admin","Administrador",hash_password("admin123"),"admin"])
    else:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'fabricacao', active INTEGER DEFAULT 1, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS prog_data (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, uploaded_by TEXT, uploaded_at TEXT DEFAULT (datetime('now')), description TEXT, semana TEXT, grupo TEXT);
        CREATE TABLE IF NOT EXISTS prog_config (id INTEGER PRIMARY KEY AUTOINCREMENT, config_json TEXT NOT NULL, updated_by TEXT, updated_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS roteiro_data (id INTEGER PRIMARY KEY AUTOINCREMENT, data_json TEXT NOT NULL, uploaded_by TEXT, uploaded_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS galva_map (id INTEGER PRIMARY KEY AUTOINCREMENT, map_json TEXT NOT NULL, uploaded_by TEXT, uploaded_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS edit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, action TEXT, detail TEXT, ts TEXT DEFAULT (datetime('now')));
        """)
        if not conn.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            conn.execute("INSERT INTO users (username,full_name,password_hash,role) VALUES (?,?,?,?)",
                         ("admin","Administrador",hash_password("admin123"),"admin"))
        conn.commit()
    conn.close()
    print("Banco inicializado OK")

try:
    init_db()
except Exception as e:
    print(f"Erro init_db: {e}")

def create_token(data, expires_delta=None):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow()+(expires_delta or timedelta(minutes=15))})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token=Depends(oauth2), db=Depends(get_db)):
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: return None
    except JWTError: return None
    user = db_fetchone(db, "SELECT * FROM users WHERE username=? AND active=1", (username,))
    return user

def require_role(*roles):
    def dep(user=Depends(get_current_user)):
        if not user: raise HTTPException(401,"Nao autenticado")
        if user["role"] not in roles: raise HTTPException(403,"Sem permissao")
        return user
    return dep

def log_action(db, username, action, detail=""):
    db_exec(db, "INSERT INTO edit_log (username,action,detail) VALUES (?,?,?)", (username,action,detail))
    if not USE_PG: db.commit()

@app.post("/api/auth/login")
def login(form=Depends(OAuth2PasswordRequestForm), db=Depends(get_db)):
    user = db_fetchone(db, "SELECT * FROM users WHERE username=? AND active=1", (form.username,))
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(400,"Usuario ou senha incorretos")
    token = create_token({"sub":user["username"]}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token":token,"token_type":"bearer",
            "user":{"username":user["username"],"full_name":user["full_name"],
                    "role":user["role"],"setores":ROLE_SETORES.get(user["role"]),
                    "prefixos":ROLE_PREFIXOS.get(user["role"])}}

@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    if not user: raise HTTPException(401,"Nao autenticado")
    return {"username":user["username"],"full_name":user["full_name"],
            "role":user["role"],"setores":ROLE_SETORES.get(user["role"]),
            "prefixos":ROLE_PREFIXOS.get(user["role"])}

@app.get("/api/data/prog")
def get_prog(db=Depends(get_db)):
    row = db_fetchone(db, "SELECT * FROM prog_data ORDER BY id DESC LIMIT 1")
    if not row: raise HTTPException(404,"Nenhuma programacao carregada")
    return {"data":json.loads(row["data_json"]),"uploaded_by":row["uploaded_by"],
            "uploaded_at":row["uploaded_at"],"semana":row.get("semana"),"grupo":row.get("grupo")}

@app.get("/api/data/prog/status")
def get_prog_status(db=Depends(get_db)):
    if USE_PG:
        rows = db_fetchall(db, "SELECT DISTINCT ON (grupo) grupo,uploaded_by,uploaded_at,semana FROM prog_data WHERE grupo IS NOT NULL ORDER BY grupo,id DESC")
    else:
        rows = db_fetchall(db, "SELECT grupo,uploaded_by,uploaded_at,semana FROM prog_data WHERE grupo IS NOT NULL GROUP BY grupo HAVING MAX(id) ORDER BY uploaded_at DESC")
    return rows

@app.post("/api/data/prog")
def upload_prog(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab")), db=Depends(get_db)):
    grupo = user["role"]
    semana = payload.get("semana","Semana "+datetime.now().strftime("%d/%m"))
    prefixos = ROLE_PREFIXOS.get(grupo)
    if prefixos:
        cts = list((payload.get("data",{}).get("cts") or {}).keys())
        invalidos = [ct for ct in cts if not any(ct.startswith(p) for p in prefixos)]
        if invalidos:
            raise HTTPException(400,f"CTs nao permitidos: {', '.join(invalidos)}")
    db_exec(db, "INSERT INTO prog_data (data_json,uploaded_by,description,semana,grupo) VALUES (?,?,?,?,?)",
            (json.dumps(payload.get("data",{})),user["username"],payload.get("description",""),semana,grupo))
    if not USE_PG: db.commit()
    log_action(db,user["username"],"upload_prog",f"{grupo} - {semana}")
    return {"ok":True}

@app.get("/api/data/config")
def get_config(db=Depends(get_db)):
    row = db_fetchone(db, "SELECT * FROM prog_config ORDER BY id DESC LIMIT 1")
    if not row: return {"config":{},"updated_by":None,"updated_at":None}
    return {"config":json.loads(row["config_json"]),"updated_by":row["updated_by"],"updated_at":row["updated_at"]}

@app.post("/api/data/config")
def save_config(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab","fabricacao")), db=Depends(get_db)):
    db_exec(db, "INSERT INTO prog_config (config_json,updated_by) VALUES (?,?)",
            (json.dumps(payload.get("config",{})),user["username"]))
    if not USE_PG: db.commit()
    return {"ok":True}

@app.get("/api/data/historico")
def get_historico(db=Depends(get_db)):
    rows = db_fetchall(db, "SELECT semana,uploaded_at,grupo,uploaded_by,data_json FROM prog_data WHERE semana IS NOT NULL ORDER BY id ASC")
    result = []
    for r in rows:
        try:
            data = json.loads(r["data_json"])
            setores = {k:v.get("carga_h",0) for k,v in (data.get("setores") or {}).items()}
        except: setores = {}
        result.append({"semana":r["semana"],"uploaded_at":r["uploaded_at"],
                       "grupo":r["grupo"],"uploaded_by":r["uploaded_by"],"setores":setores})
    return result

@app.get("/api/data/galvamap")
def get_galvamap(db=Depends(get_db)):
    row = db_fetchone(db, "SELECT * FROM galva_map ORDER BY id DESC LIMIT 1")
    if not row: return {"map":{},"uploaded_by":None,"uploaded_at":None}
    return {"map":json.loads(row["map_json"]),"uploaded_by":row["uploaded_by"],"uploaded_at":row["uploaded_at"]}

@app.post("/api/data/galvamap")
def upload_galvamap(payload: dict, user=Depends(require_role("admin")), db=Depends(get_db)):
    db_exec(db, "INSERT INTO galva_map (map_json,uploaded_by) VALUES (?,?)",
            (json.dumps(payload.get("map",{})),user["username"]))
    if not USE_PG: db.commit()
    log_action(db,user["username"],"upload_galvamap",str(len(payload.get("map",{}))))
    return {"ok":True}

@app.get("/api/data/roteiro")
def get_roteiro(db=Depends(get_db)):
    row = db_fetchone(db, "SELECT * FROM roteiro_data ORDER BY id DESC LIMIT 1")
    if not row: raise HTTPException(404,"Nenhum roteiro carregado")
    return {"data":json.loads(row["data_json"]),"uploaded_by":row["uploaded_by"],"uploaded_at":row["uploaded_at"]}

@app.post("/api/data/roteiro")
def upload_roteiro(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab")), db=Depends(get_db)):
    db_exec(db, "INSERT INTO roteiro_data (data_json,uploaded_by) VALUES (?,?)",
            (json.dumps(payload.get("data",{})),user["username"]))
    if not USE_PG: db.commit()
    return {"ok":True}

@app.post("/api/data/edit")
def save_edit(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab","fabricacao")), db=Depends(get_db)):
    log_action(db,user["username"],"edit_indir",json.dumps(payload))
    return {"ok":True}

@app.get("/api/data/log")
def get_log(limit: int=100, user=Depends(require_role("admin")), db=Depends(get_db)):
    return db_fetchall(db, "SELECT * FROM edit_log ORDER BY id DESC LIMIT ?", (limit,))

@app.get("/api/users")
def list_users(user=Depends(require_role("admin")), db=Depends(get_db)):
    return db_fetchall(db, "SELECT id,username,full_name,role,active,created_at FROM users")

@app.post("/api/users")
def create_user(payload: dict, user=Depends(require_role("admin")), db=Depends(get_db)):
    try:
        db_exec(db, "INSERT INTO users (username,full_name,password_hash,role) VALUES (?,?,?,?)",
                (payload["username"],payload.get("full_name",""),
                 hash_password(payload["password"]),payload.get("role","fabricacao")))
        if not USE_PG: db.commit()
        return {"ok":True}
    except Exception as e:
        raise HTTPException(400,str(e))

@app.put("/api/users/{uid}")
def update_user(uid: int, payload: dict, user=Depends(require_role("admin")), db=Depends(get_db)):
    sets,vals=[],[]
    for f in ["full_name","role","active"]:
        if f in payload: sets.append(f"{f}=?"); vals.append(payload[f])
    if "password" in payload:
        sets.append("password_hash=?"); vals.append(hash_password(payload["password"]))
    if not sets: raise HTTPException(400,"Nada para atualizar")
    vals.append(uid)
    db_exec(db, f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
    if not USE_PG: db.commit()
    return {"ok":True}

frontend_path = os.path.join(os.path.dirname(__file__),"../frontend")
if os.path.exists(frontend_path):
    app.mount("/",StaticFiles(directory=frontend_path,html=True),name="static")
