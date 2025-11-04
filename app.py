from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from sqlalchemy import Column, Integer, String, Boolean, Date, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from typing import Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
import random, string

# =====================
# Config / DB
# =====================
DATABASE_URL = "postgresql+psycopg://license_db_5mhk_user:U6bX1FbyAxN22UJ15GxwfLimTH9KHOyv@dpg-d2joqpur433s738207r0-a.oregon-postgres.render.com:5432/license_db_5mhk"

Base = declarative_base()
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI()

# =====================
# JWT / Admin
# =====================
SECRET_KEY = "super-secret-key-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
ADMIN_USERNAME = "motherfucker"
ADMIN_PASSWORD = "Nos+24682468"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Login gerekli")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Geçersiz token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Token hatalı")

# =====================
# DB Model
# =====================
class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, nullable=False)
    license_key = Column(String, nullable=False, unique=True)
    expires_on = Column(Date, nullable=False)
    active = Column(Boolean, default=True)
    bound_mac = Column(String, nullable=True)
    client_secret = Column(String, nullable=True)
    notes = Column(String, nullable=True)
    cpu = Column(String, nullable=True)
    bios_uuid = Column(String, nullable=True)
    disk_serial = Column(String, nullable=True)

# =====================
# DB Dependency
# =====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =====================
# HTML Template
# =====================
def base_html(title: str, content: str) -> str:
    return f"""
    <!DOCTYPE html>
    <html lang="tr" data-bs-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{title}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background-color: #121212; color: #e0e0e0; }}
            .table {{ background-color: #1e1e1e; }}
            .table th, .table td {{ color: #f5f5f5; }}
            .btn {{ border-radius: 8px; }}
        </style>
    </head>
    <body>
        <div class="container py-4">
            {content}
        </div>
    </body>
    </html>
    """

# =====================
# Login / Logout
# =====================
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return base_html("Login", """
    <div class="row justify-content-center">
      <div class="col-md-4">
        <div class="card shadow-lg p-4 bg-secondary">
          <h3 class="text-center mb-3">🔐 Admin Girişi</h3>
          <form method="post" action="/login">
            <div class="mb-3">
              <label class="form-label">Kullanıcı Adı</label>
              <input type="text" class="form-control" name="username" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Şifre</label>
              <input type="password" class="form-control" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Giriş Yap</button>
          </form>
        </div>
      </div>
    </div>
    """)

@app.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return HTMLResponse(content=base_html("Login Hata", """
        <div class="alert alert-danger">❌ Hatalı kullanıcı adı veya şifre</div>
        <a href="/login" class="btn btn-secondary">Tekrar dene</a>
        """))
    token = create_access_token(data={"sub": username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True)
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response

# =====================
# Lisans Anahtarı Üretici
# =====================
def generate_license_key(length=16):
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

# =====================
# Admin Panel
# =====================
@app.get("/", response_class=HTMLResponse)
async def admin_panel(db: Session = Depends(get_db), username: str = Depends(get_current_user)):
    licenses = db.query(License).all()
    rows = "".join([
        f"""
        <tr>
            <td>{x.id}</td>
            <td>{x.username}</td>
            <td>{x.license_key}</td>
            <td>{x.expires_on}</td>
            <td>{"✅" if x.active else "❌"}</td>
            <td>{x.bound_mac or '-'}</td>
            <td>{x.client_secret or '-'}</td>
            <td>{x.cpu or '-'}</td>
            <td>{x.bios_uuid or '-'}</td>
            <td>{x.disk_serial or '-'}</td>
            <td>{x.notes or ''}</td>
            <td>
                <a class="btn btn-sm btn-primary" href="/edit/{x.id}">Düzenle</a>
                <a class="btn btn-sm btn-danger" href="/delete/{x.id}">Sil</a>
            </td>
        </tr>
        """ for x in licenses
    ])
    content = f"""
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h1 class="h3">📋 Lisans Yönetimi</h1>
        <div>
            <a class="btn btn-success" href="/create">+ Yeni Lisans</a>
            <a class="btn btn-danger" href="/logout">Çıkış</a>
        </div>
    </div>
    <table class="table table-striped table-bordered table-hover">
        <thead class="table-dark">
            <tr>
                <th>ID</th>
                <th>Kullanıcı</th>
                <th>Lisans Anahtarı</th>
                <th>Bitiş Tarihi</th>
                <th>Durum</th>
                <th>MAC</th>
                <th>Client Secret</th>
                <th>CPU</th>
                <th>BIOS UUID</th>
                <th>Disk Serial</th>
                <th>Not</th>
                <th>İşlem</th>
            </tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    """
    return base_html("Lisans Yönetimi", content)

# =====================
# Lisans CRUD
# =====================
@app.get("/create", response_class=HTMLResponse)
async def create_form(_: str = Depends(get_current_user)):
    default_date = (datetime.utcnow() + timedelta(days=30)).strftime("%Y-%m-%d")
    auto_key = generate_license_key()
    content = f"""
    <h2 class="mb-3">Yeni Lisans Ekle</h2>
    <form action="/create" method="post" class="row g-3">
        <div class="col-md-6">
            <label class="form-label">Kullanıcı</label>
            <input type="text" name="username" class="form-control" required>
        </div>
        <div class="col-md-6">
            <label class="form-label">Lisans Anahtarı</label>
            <input type="text" name="license_key" class="form-control" value="{auto_key}" readonly required>
        </div>
        <div class="col-md-6">
            <label class="form-label">Bitiş Tarihi (DD-MM-YYYY)</label>
            <input type="text" name="expires_on" class="form-control" value="{default_date}" required>
        </div>
        <div class="col-md-6">
            <label class="form-label">MAC</label>
            <input type="text" name="bound_mac" class="form-control">
        </div>
        <div class="col-md-6">
            <label class="form-label">Client Secret</label>
            <input type="text" name="client_secret" class="form-control">
        </div>
        <div class="col-md-6">
            <label class="form-label">CPU</label>
            <input type="text" name="cpu" class="form-control">
        </div>
        <div class="col-md-6">
            <label class="form-label">BIOS UUID</label>
            <input type="text" name="bios_uuid" class="form-control">
        </div>
        <div class="col-md-6">
            <label class="form-label">Disk Serial</label>
            <input type="text" name="disk_serial" class="form-control">
        </div>
        <div class="col-12">
            <label class="form-label">Not</label>
            <input type="text" name="notes" class="form-control">
        </div>
        <div class="col-12 form-check">
            <input class="form-check-input" type="checkbox" name="active" checked>
            <label class="form-check-label">Aktif mi?</label>
        </div>
        <div class="col-12">
            <button type="submit" class="btn btn-success">Lisans Oluştur</button>
            <a href="/" class="btn btn-secondary">Geri</a>
        </div>
    </form>
    """
    return base_html("Yeni Lisans", content)

@app.post("/create")
async def create_license(
    username: str = Form(...),
    license_key: str = Form(...),
    expires_on: str = Form(...),
    active: Optional[str] = Form(None),
    bound_mac: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    cpu: Optional[str] = Form(None),
    bios_uuid: Optional[str] = Form(None),
    disk_serial: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user)
):
    lic = License(
        username=username,
        license_key=license_key,
        expires_on=datetime.strptime(expires_on, "%Y-%m-%d"),
        active=True if active else False,
        bound_mac=bound_mac,
        client_secret=client_secret,
        cpu=cpu,
        bios_uuid=bios_uuid,
        disk_serial=disk_serial,
        notes=notes
    )
    db.add(lic)
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/edit/{license_id}", response_class=HTMLResponse)
async def edit_form(license_id: int, db: Session = Depends(get_db), _: str = Depends(get_current_user)):
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    checked = "checked" if lic.active else ""
    content = f"""
    <h2 class="mb-3">Lisans Düzenle</h2>
    <form action="/edit/{lic.id}" method="post" class="row g-3">
        <div class="col-md-6"><label class="form-label">Kullanıcı</label><input type="text" name="username" value="{lic.username}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">Lisans Anahtarı</label><input type="text" name="license_key" value="{lic.license_key}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">Bitiş Tarihi</label><input type="text" name="expires_on" value="{lic.expires_on}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">MAC</label><input type="text" name="bound_mac" value="{lic.bound_mac or ''}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">Client Secret</label><input type="text" name="client_secret" value="{lic.client_secret or ''}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">CPU</label><input type="text" name="cpu" value="{lic.cpu or ''}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">BIOS UUID</label><input type="text" name="bios_uuid" value="{lic.bios_uuid or ''}" class="form-control"></div>
        <div class="col-md-6"><label class="form-label">Disk Serial</label><input type="text" name="disk_serial" value="{lic.disk_serial or ''}" class="form-control"></div>
        <div class="col-12"><label class="form-label">Not</label><input type="text" name="notes" value="{lic.notes or ''}" class="form-control"></div>
        <div class="col-12 form-check"><input class="form-check-input" type="checkbox" name="active" {checked}><label class="form-check-label">Aktif mi?</label></div>
        <div class="col-12"><button type="submit" class="btn btn-primary">Kaydet</button><a href="/" class="btn btn-secondary">Geri</a></div>
    </form>
    """
    return base_html("Lisans Düzenle", content)

@app.post("/edit/{license_id}")
async def edit_license(
    license_id: int,
    username: str = Form(...),
    license_key: str = Form(...),
    expires_on: str = Form(...),
    active: Optional[str] = Form(None),
    bound_mac: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    cpu: Optional[str] = Form(...),
    bios_uuid: Optional[str] = Form(...),
    disk_serial: Optional[str] = Form(...),
    notes: Optional[str] = Form(...),
    db: Session = Depends(get_db),
    _: str = Depends(get_current_user)
):
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(status_code=404, detail="Lisans bulunamadı")
    lic.username = username
    lic.license_key = license_key
    lic.expires_on = datetime.strptime(expires_on, "%Y-%m-%d")
    lic.active = True if active else False
    lic.bound_mac = bound_mac
    lic.client_secret = client_secret
    lic.cpu = cpu
    lic.bios_uuid = bios_uuid
    lic.disk_serial = disk_serial
    lic.notes = notes
    db.commit()
    return RedirectResponse(url="/", status_code=303)

@app.get("/delete/{license_id}")
async def delete_license(license_id: int, db: Session = Depends(get_db), _: str = Depends(get_current_user)):
    lic = db.query(License).filter(License.id == license_id).first()
    if lic:
        db.delete(lic)
        db.commit()
    return RedirectResponse(url="/", status_code=303)

# =====================
# Lisans Doğrulama API
# =====================
@app.post("/api/verify")
async def verify_license(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        username = data.get("username")
        license_key = data.get("key")
        mac = data.get("mac") or None
        cpu = data.get("cpu") or None
        bios_uuid = data.get("bios_uuid") or None
        disk_serial = data.get("disk_serial") or None
        client_secret = data.get("client_secret") or None

        if not username or not license_key:
            return {"status": False, "message": "Kullanıcı adı veya lisans anahtarı eksik"}

        lic = db.query(License).filter(License.username == username, License.license_key == license_key).first()
        if not lic:
            return {"status": False, "message": "Kullanıcı adı veya lisans bulunamadı"}
        if not lic.active:
            return {"status": False, "message": "Lisans pasif"}
        if lic.expires_on < datetime.utcnow().date():
            return {"status": False, "message": "Lisans süresi dolmuş"}

        # İlk girişte boş ise kaydet
        updated = False
        if not lic.bound_mac and mac:
            lic.bound_mac = mac
            updated = True
        if not lic.cpu and cpu:
            lic.cpu = cpu
            updated = True
        if not lic.bios_uuid and bios_uuid:
            lic.bios_uuid = bios_uuid
            updated = True
        if not lic.disk_serial and disk_serial:
            lic.disk_serial = disk_serial
            updated = True
        if not lic.client_secret and client_secret:
            lic.client_secret = client_secret
            updated = True

        # Eğer daha önce kaydedildiyse -> kontrol et
        if lic.bound_mac and mac and lic.bound_mac != mac:
            return {"status": False, "message": "Farklı cihaz (MAC uyuşmuyor)"}
        if lic.cpu and cpu and lic.cpu != cpu:
            return {"status": False, "message": "Farklı cihaz (CPU uyuşmuyor)"}
        if lic.bios_uuid and bios_uuid and lic.bios_uuid != bios_uuid:
            return {"status": False, "message": "Farklı cihaz (BIOS uyuşmuyor)"}
        if lic.disk_serial and disk_serial and lic.disk_serial != disk_serial:
            return {"status": False, "message": "Farklı cihaz (Disk uyuşmuyor)"}
        if lic.client_secret and client_secret and lic.client_secret != client_secret:
            return {"status": False, "message": "Farklı cihaz (Secret uyuşmuyor)"}

        if updated:
            db.commit()

        return {"status": True, "message": "Lisans geçerli"}
    except Exception as e:
        return {"status": False, "message": str(e)}

# =====================
# DB Oluşturma
# =====================
Base.metadata.create_all(bind=engine)
