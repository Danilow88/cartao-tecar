import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from urllib.parse import quote
from models import init_db, get_card, save_card, verify_admin

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-prod")
SESSION_COOKIE = "admin_session"
UPLOAD_DIR = Path("static/uploads")
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp"}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.filters["urlencode"] = lambda s: quote(str(s), safe="")
serializer = URLSafeTimedSerializer(SECRET_KEY)


@app.on_event("startup")
def on_startup():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    init_db()


def get_session(request: Request) -> bool:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    try:
        serializer.loads(token, max_age=86400)
        return True
    except (BadSignature, SignatureExpired):
        return False


def make_session_token() -> str:
    return serializer.dumps("admin")


async def _save_upload(upload: UploadFile, prefix: str) -> str:
    """Valida e salva upload. Retorna path relativo ou string vazia."""
    if not upload or not upload.filename:
        return ""
    if upload.content_type not in ALLOWED_TYPES:
        raise ValueError("Tipo inválido")
    content = await upload.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise ValueError("Arquivo muito grande (máx 5MB)")
    ext = Path(upload.filename).suffix.lower() or ".jpg"
    filename = f"{prefix}_{uuid.uuid4().hex}{ext}"
    (UPLOAD_DIR / filename).write_bytes(content)
    return f"uploads/{filename}"


# ── Rota pública ──────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def card(request: Request):
    return templates.TemplateResponse("card.html", {"request": request, "card": get_card()})


# ── Login ─────────────────────────────────────────────────────
@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = ""):
    if get_session(request):
        return RedirectResponse("/admin", status_code=302)
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@app.post("/admin/login")
async def login(username: str = Form(...), password: str = Form(...)):
    if verify_admin(username, password):
        token = make_session_token()
        resp = RedirectResponse("/admin", status_code=302)
        resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return resp
    return RedirectResponse("/admin/login?error=Credenciais+inválidas", status_code=302)


@app.post("/admin/logout")
async def logout():
    resp = RedirectResponse("/admin/login", status_code=302)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── Admin ─────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)
    return templates.TemplateResponse("admin.html", {"request": request, "card": get_card()})


@app.post("/admin/save")
async def admin_save(
    request: Request,
    nome: str = Form(""),
    telefone: str = Form(""),
    endereco: str = Form(""),
    foto: UploadFile = File(None),
    logo: UploadFile = File(None),
    bg: UploadFile = File(None),
):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    try:
        foto_path = await _save_upload(foto, "foto")
        logo_path = await _save_upload(logo, "logo")
        bg_path   = await _save_upload(bg,   "bg")
    except ValueError as e:
        return RedirectResponse(f"/admin?error={e}", status_code=302)

    save_card(nome, telefone, endereco, foto_path, logo_path, bg_path)
    return RedirectResponse("/admin?saved=1", status_code=302)
