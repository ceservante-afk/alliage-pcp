from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from datetime import datetime, timedelta
import json, os, hashlib, hmac, base64, sqlite3, re

SECRET_KEY = os.environ.get("SECRET_KEY", "alliage2026pcp")
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480
DB_PATH = "/tmp/pcp.db"
DATABASE_URL = os.environ.get("DATABASE_URL", "")

ROLE_SETORES = {
    "pcp_metal": ["SOLDA ELÉTRICA", "ESTAMPARIA", "USINAGEM", "MICRO/USINAGEM"],
    "pcp_acab":  ["PINTURA", "GALVANOPLASTIA"],
    "admin": None, "fabricacao": None, "visitante": None,
}
ROLE_PREFIXOS = {
    "pcp_metal": ["ESTA", "USIN", "MUSI"],
    "pcp_acab":  ["PINP", "PINL", "GALV"],
    "admin": None,
}

app = FastAPI(title="Alliage PCP", version="3.1.0")
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

USE_PG = bool(DATABASE_URL)

def get_pg_conn():
    import pg8000.native, urllib.parse
    m = re.match(r'postgresql://([^:]+):(.+)@([^:/]+):(\d+)/(.+)', DATABASE_URL)
    if not m:
        raise ValueError("DATABASE_URL invalida")
    user, password, host, port, database = m.groups()
    password = urllib.parse.unquote(password)
    return pg8000.native.Connection(
        host=host, port=int(port), database=database,
        user=user, password=password, ssl_context=True
    )

def get_sqlite_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    if USE_PG:
        conn = get_pg_conn()
        try: yield conn
        finally:
            try: conn.close()
            except: pass
    else:
        conn = get_sqlite_conn()
        try: yield conn
        finally: conn.close()

def pg_run(conn, sql, params=()):
    """
    Converte ? para :p0, :p1, :p2 ... e executa no pg8000.native
    que aceita named params via **kwargs
    """
    idx = 0
    new_sql = ""
    for ch in sql:
        if ch == "?":
            new_sql += f":p{idx}"
            idx += 1
        else:
            new_sql += ch
    kwargs = {f"p{i}": v for i, v in enumerate(params)}
    return conn.run(new_sql, **kwargs)

class DB:
    def __init__(self, conn):
        self.conn = conn
        self.is_pg = USE_PG

    def exec(self, sql, params=()):
        if self.is_pg:
            pg_run(self.conn, sql, params)
        else:
            self.conn.execute(sql, params)
            self.conn.commit()

    def fetchone(self, sql, params=()):
        if self.is_pg:
            rows = pg_run(self.conn, sql, params)
            if not rows: return None
            cols = [c['name'] for c in self.conn.columns]
            return dict(zip(cols, rows[0]))
        else:
            self.conn.row_factory = sqlite3.Row
            cur = self.conn.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None

    def fetchall(self, sql, params=()):
        if self.is_pg:
            rows = pg_run(self.conn, sql, params)
            cols = [c['name'] for c in self.conn.columns]
            return [dict(zip(cols,r)) for r in rows]
        else:
            self.conn.row_factory = sqlite3.Row
            cur = self.conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def log(self, username, action, detail=""):
        self.exec("INSERT INTO edit_log (username,action,detail) VALUES (?,?,?)",
                  (username, action, detail))

def get_db_wrapper(conn=Depends(get_db)):
    return DB(conn)

def init_db():
    if USE_PG:
        conn = get_pg_conn()
        stmts = [
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
        for s in stmts:
            conn.run(s)
        rows = conn.run("SELECT id FROM users WHERE username='admin'")
        if not rows:
            conn.run(
                "INSERT INTO users (username,full_name,password_hash,role) VALUES (:p0,:p1,:p2,:p3)",
                p0="admin", p1="Administrador", p2=hash_password("admin123"), p3="admin"
            )
        conn.close()
    else:
        conn = get_sqlite_conn()
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
    print(f"Banco OK ({'PostgreSQL' if USE_PG else 'SQLite'})")

try:
    init_db()
except Exception as e:
    print(f"ERRO init_db: {e}")
    import traceback; traceback.print_exc()

def create_token(data, expires_delta=None):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow()+(expires_delta or timedelta(minutes=15))})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token=Depends(oauth2), db: DB=Depends(get_db_wrapper)):
    if not token: return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username: return None
    except JWTError: return None
    return db.fetchone("SELECT * FROM users WHERE username=? AND active=1", (username,))

def require_role(*roles):
    def dep(user=Depends(get_current_user)):
        if not user: raise HTTPException(401,"Nao autenticado")
        if user["role"] not in roles: raise HTTPException(403,"Sem permissao")
        return user
    return dep

@app.post("/api/auth/login")
def login(form=Depends(OAuth2PasswordRequestForm), db: DB=Depends(get_db_wrapper)):
    user = db.fetchone("SELECT * FROM users WHERE username=? AND active=1", (form.username,))
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
def get_prog(db: DB=Depends(get_db_wrapper)):
    # Buscar o registro mais recente de cada grupo e mesclar os CTs
    if USE_PG:
        rows = db.fetchall(
            "SELECT DISTINCT ON (grupo) grupo,data_json,uploaded_by,uploaded_at,semana "
            "FROM prog_data ORDER BY grupo, id DESC"
        )
    else:
        rows = db.fetchall(
            "SELECT grupo,data_json,uploaded_by,uploaded_at,semana FROM prog_data "
            "WHERE id IN (SELECT MAX(id) FROM prog_data GROUP BY grupo) ORDER BY id DESC"
        )
    if not rows:
        raise HTTPException(404,"Nenhuma programacao carregada")

    # Mesclar dados: CTs de cada grupo são independentes
    merged_cts = {}
    merged_setores = {}
    last_row = rows[0]  # metadados do registro mais recente

    for row in reversed(rows):  # mais antigos primeiro, mais recentes sobrescrevem
        d = json.loads(row["data_json"])
        merged_cts.update(d.get("cts") or {})
        merged_setores.update(d.get("setores") or {})
        last_row = row  # o último processado é o mais recente

    # Recalcular carga dos setores com base nos CTs mesclados
    for cat, setor in merged_setores.items():
        total_h = 0
        total_n = 0
        for ct in setor.get("cts", []):
            if ct in merged_cts:
                total_h += merged_cts[ct].get("carga_total_h", 0)
                total_n += merged_cts[ct].get("n_itens", 0)
        setor["carga_h"] = round(total_h, 2)
        setor["n_itens"] = total_n

    merged_data = {"cts": merged_cts, "setores": merged_setores}

    return {
        "data": merged_data,
        "uploaded_by": last_row["uploaded_by"],
        "uploaded_at": last_row["uploaded_at"],
        "semana": last_row.get("semana"),
        "grupo": last_row.get("grupo")
    }

@app.get("/api/data/prog/status")
def get_prog_status(db: DB=Depends(get_db_wrapper)):
    if USE_PG:
        return db.fetchall("SELECT DISTINCT ON (grupo) grupo,uploaded_by,uploaded_at,semana FROM prog_data WHERE grupo IS NOT NULL ORDER BY grupo,id DESC")
    return db.fetchall("SELECT grupo,uploaded_by,uploaded_at,semana FROM prog_data WHERE grupo IS NOT NULL GROUP BY grupo HAVING MAX(id) ORDER BY uploaded_at DESC")

@app.post("/api/data/prog")
def upload_prog(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab")), db: DB=Depends(get_db_wrapper)):
    grupo = user["role"]
    semana = payload.get("semana","Semana "+datetime.now().strftime("%d/%m"))
    prefixos = ROLE_PREFIXOS.get(grupo)
    if prefixos:
        cts = list((payload.get("data",{}).get("cts") or {}).keys())
        invalidos = [ct for ct in cts if not any(ct.startswith(p) for p in prefixos)]
        if invalidos:
            raise HTTPException(400,f"CTs nao permitidos: {', '.join(invalidos)}")
    db.exec("INSERT INTO prog_data (data_json,uploaded_by,description,semana,grupo) VALUES (?,?,?,?,?)",
            (json.dumps(payload.get("data",{})),user["username"],payload.get("description",""),semana,grupo))
    db.log(user["username"],"upload_prog",f"{grupo} - {semana}")
    return {"ok":True}

@app.get("/api/data/config")
def get_config(db: DB=Depends(get_db_wrapper)):
    row = db.fetchone("SELECT * FROM prog_config ORDER BY id DESC LIMIT 1")
    if not row: return {"config":{},"updated_by":None,"updated_at":None}
    return {"config":json.loads(row["config_json"]),"updated_by":row["updated_by"],"updated_at":row["updated_at"]}

@app.post("/api/data/config")
def save_config(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab","fabricacao")), db: DB=Depends(get_db_wrapper)):
    db.exec("INSERT INTO prog_config (config_json,updated_by) VALUES (?,?)",
            (json.dumps(payload.get("config",{})),user["username"]))
    return {"ok":True}

@app.get("/api/data/historico")
def get_historico(db: DB=Depends(get_db_wrapper)):
    rows = db.fetchall("SELECT semana,uploaded_at,grupo,uploaded_by,data_json FROM prog_data WHERE semana IS NOT NULL ORDER BY id ASC")
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
def get_galvamap(db: DB=Depends(get_db_wrapper)):
    row = db.fetchone("SELECT * FROM galva_map ORDER BY id DESC LIMIT 1")
    if not row: return {"map":{},"uploaded_by":None,"uploaded_at":None}
    return {"map":json.loads(row["map_json"]),"uploaded_by":row["uploaded_by"],"uploaded_at":row["uploaded_at"]}

@app.post("/api/data/galvamap")
def upload_galvamap(payload: dict, user=Depends(require_role("admin")), db: DB=Depends(get_db_wrapper)):
    db.exec("INSERT INTO galva_map (map_json,uploaded_by) VALUES (?,?)",
            (json.dumps(payload.get("map",{})),user["username"]))
    db.log(user["username"],"upload_galvamap",str(len(payload.get("map",{}))))
    return {"ok":True}

@app.get("/api/data/roteiro")
def get_roteiro(db: DB=Depends(get_db_wrapper)):
    row = db.fetchone("SELECT * FROM roteiro_data ORDER BY id DESC LIMIT 1")
    if not row: raise HTTPException(404,"Nenhum roteiro carregado")
    return {"data":json.loads(row["data_json"]),"uploaded_by":row["uploaded_by"],"uploaded_at":row["uploaded_at"]}

@app.post("/api/data/roteiro")
def upload_roteiro(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab")), db: DB=Depends(get_db_wrapper)):
    db.exec("INSERT INTO roteiro_data (data_json,uploaded_by) VALUES (?,?)",
            (json.dumps(payload.get("data",{})),user["username"]))
    return {"ok":True}

@app.post("/api/data/edit")
def save_edit(payload: dict, user=Depends(require_role("admin","pcp_metal","pcp_acab","fabricacao")), db: DB=Depends(get_db_wrapper)):
    db.log(user["username"],"edit_indir",json.dumps(payload))
    return {"ok":True}

@app.get("/api/data/log")
def get_log(limit: int=100, user=Depends(require_role("admin")), db: DB=Depends(get_db_wrapper)):
    return db.fetchall("SELECT * FROM edit_log ORDER BY id DESC LIMIT ?", (limit,))

@app.get("/api/users")
def list_users(user=Depends(require_role("admin")), db: DB=Depends(get_db_wrapper)):
    return db.fetchall("SELECT id,username,full_name,role,active,created_at FROM users")

@app.post("/api/users")
def create_user(payload: dict, user=Depends(require_role("admin")), db: DB=Depends(get_db_wrapper)):
    try:
        db.exec("INSERT INTO users (username,full_name,password_hash,role) VALUES (?,?,?,?)",
                (payload["username"],payload.get("full_name",""),
                 hash_password(payload["password"]),payload.get("role","fabricacao")))
        return {"ok":True}
    except Exception as e:
        raise HTTPException(400,str(e))

@app.put("/api/users/{uid}")
def update_user(uid: int, payload: dict, user=Depends(require_role("admin")), db: DB=Depends(get_db_wrapper)):
    sets,vals=[],[]
    for f in ["full_name","role","active"]:
        if f in payload: sets.append(f"{f}=?"); vals.append(payload[f])
    if "password" in payload:
        sets.append("password_hash=?"); vals.append(hash_password(payload["password"]))
    if not sets: raise HTTPException(400,"Nada para atualizar")
    vals.append(uid)
    db.exec(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals)
    return {"ok":True}

frontend_path = os.path.join(os.path.dirname(__file__),"../frontend")
if os.path.exists(frontend_path):
    app.mount("/",StaticFiles(directory=frontend_path,html=True),name="static")
