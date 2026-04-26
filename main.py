import os
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from models import init_db, get_card, save_card, verify_admin

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-prod")
SESSION_COOKIE = "admin_session"
UPLOAD_DIR = Path("static/uploads")
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2MB
ALLOWED_TYPES = {"image/jpeg", "image/png"}

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
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
        serializer.loads(token, max_age=86400)  # 24h
        return True
    except (BadSignature, SignatureExpired):
        return False


def make_session_token() -> str:
    return serializer.dumps("admin")


# ── Rota pública ──────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def card(request: Request):
    data = get_card()
    return templates.TemplateResponse("card.html", {"request": request, "card": data})


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
        response = RedirectResponse("/admin", status_code=302)
        response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax")
        return response
    return RedirectResponse("/admin/login?error=Credenciais+inválidas", status_code=302)


@app.post("/admin/logout")
async def logout():
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


# ── Admin ─────────────────────────────────────────────────────
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)
    data = get_card()
    return templates.TemplateResponse("admin.html", {"request": request, "card": data})


@app.post("/admin/save")
async def admin_save(
    request: Request,
    nome: str = Form(...),
    telefone: str = Form(...),
    endereco: str = Form(...),
    foto: UploadFile = File(None),
    logo: UploadFile = File(None),
):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    foto_path = ""
    logo_path = ""

    for upload, field in [(foto, "foto"), (logo, "logo")]:
        if upload and upload.filename:
            if upload.content_type not in ALLOWED_TYPES:
                return RedirectResponse("/admin?error=Tipo+de+arquivo+inválido", status_code=302)
            content = await upload.read()
            if len(content) > MAX_UPLOAD_SIZE:
                return RedirectResponse("/admin?error=Arquivo+muito+grande+(máx+2MB)", status_code=302)
            ext = Path(upload.filename).suffix
            filename = f"{field}_{uuid.uuid4().hex}{ext}"
            filepath = UPLOAD_DIR / filename
            filepath.write_bytes(content)
            if field == "foto":
                foto_path = f"uploads/{filename}"
            else:
                logo_path = f"uploads/{filename}"

    save_card(nome, telefone, endereco, foto_path, logo_path)
    return RedirectResponse("/admin?saved=1", status_code=302)
