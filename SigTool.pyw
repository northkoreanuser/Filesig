"""
SigTool — 키 생성 / 서명 / 검증
의존 패키지는 실행 시 자동 설치됩니다.
"""

# ── 자동 설치 ─────────────────────────────────────────────
import subprocess
import sys


def _ensure(pip_name: str, import_name: str | None = None) -> None:
    try:
        __import__(import_name or pip_name)
    except ImportError:
        print(f"[SigTool] '{pip_name}' 설치 중...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pip_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"[SigTool] '{pip_name}' 설치 완료")


_ensure("cryptography")
_ensure("requests")
_ensure("tkinterdnd2")

# ── 일반 임포트 ───────────────────────────────────────────
import configparser
import hashlib
import os
import re
import threading
import tkinter as tk

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from tkinterdnd2 import DND_FILES, TkinterDnD

# ── 경로 상수 ─────────────────────────────────────────────
SCRIPT_DIR    = os.path.dirname(os.path.abspath(__file__))
SCRIPT_STEM   = os.path.splitext(os.path.basename(__file__))[0]
INI_PATH      = os.path.join(SCRIPT_DIR, SCRIPT_STEM + ".ini")
LOCAL_PRIV    = os.path.join(SCRIPT_DIR, "private.pem")
LOCAL_PUB     = os.path.join(SCRIPT_DIR, "public.pem")
LOCAL_FILESIG = os.path.join(SCRIPT_DIR, "Filesig")
PUB_CACHE     = os.path.join(SCRIPT_DIR, ".pub_cache.pem")  # GitHub 공개키 파일 캐시
PUB_CACHE_TTL = 24 * 3600  # 캐시 유효 기간 (초)


# ── URL → (id, repo, branch) 추출 ───────────────────────
def _parse_gh_url(url: str) -> tuple[str, str, str]:
    """
    지원 형식:
      https://github.com/{id}/{repo}
      https://github.com/{id}/{repo}/tree/{branch}
      https://github.com/{id}/{repo}/tree/{branch}/Filesig
    반환: (id, repo, branch) 또는 ("", "", "")
    branch 미지정 시 "main" 기본값.
    """
    url = url.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+)(?:/tree/([^/]+))?(?:/.*)?$", url)
    if m:
        return m.group(1), m.group(2), m.group(3) or "main"
    return "", "", ""


# ── INI 로드 / 생성 ──────────────────────────────────────
VERIFY_TTL = 24 * 3600   # 재검증 주기 (초)


def _save_ini(cfg: configparser.ConfigParser) -> None:
    with open(INI_PATH, "w", encoding="utf-8") as f:
        cfg.write(f)


def _load_ini() -> tuple[str, str, str, bool]:
    """(gh_id, gh_repo, gh_branch, force_local) 반환.

    [github]
        url = https://github.com/{id}/{repo}         ← branch 생략 시 main
        url = https://github.com/{id}/{repo}/tree/dev ← branch 지정 가능

    [cache]
        verified    = true | false
        verified_at = Unix 타임스탬프
        pages       = true | false
        pages_at    = Unix 타임스탬프

    verified / pages 가 false 이면 TTL 무시하고 매번 재검증.
    true 이고 TTL 이내이면 네트워크 호출 없이 캐시 사용.
    """
    import time
    cfg = configparser.ConfigParser()

    # ── ini 없음 → 템플릿 생성 후 로컬 강제 ──────────────
    if not os.path.isfile(INI_PATH):
        cfg["github"] = {"url": ""}
        cfg["cache"]  = {
            "verified": "false", "verified_at": "0",
            "pages":    "false", "pages_at":    "0",
        }
        _save_ini(cfg)
        return "", "", "", True

    cfg.read(INI_PATH, encoding="utf-8")
    raw_url = cfg.get("github", "url", fallback="").strip()
    gh_id, gh_repo, gh_branch = _parse_gh_url(raw_url)

    if not (gh_id and gh_repo):
        return "", "", "", True

    # ── 캐시 읽기 ─────────────────────────────────────────
    def _get_cached(key_val: str, key_at: str) -> tuple[bool, float]:
        ok = cfg.get("cache", key_val, fallback="false").strip().lower() == "true"
        try:
            at = float(cfg.get("cache", key_at, fallback="0"))
        except ValueError:
            at = 0.0
        return ok, at

    cached_ok, verified_at = _get_cached("verified", "verified_at")
    age = time.time() - verified_at

    # false 이면 TTL 무시하고 항상 재검증
    if cached_ok and age < VERIFY_TTL:
        return gh_id, gh_repo, gh_branch, False

    # ── 재검증 ────────────────────────────────────────────
    ok = False
    try:
        r = requests.get(
            f"https://api.github.com/repos/{gh_id}/{gh_repo}",
            timeout=6,
            headers={"Accept": "application/vnd.github+json"},
        )
        ok = r.status_code == 200
    except Exception:
        pass

    if "cache" not in cfg:
        cfg["cache"] = {}
    cfg["cache"]["verified"]    = "true" if ok else "false"
    cfg["cache"]["verified_at"] = str(int(time.time()))
    if not ok:
        cfg["cache"]["pages"]    = "false"
        cfg["cache"]["pages_at"] = "0"
    _save_ini(cfg)

    return (gh_id, gh_repo, gh_branch, False) if ok else ("", "", "", True)


def _check_pages(gh_id: str, gh_repo: str) -> bool:
    """GitHub Pages 존재 여부.
    pages = false 이면 TTL 무시하고 매번 재시도.
    """
    import time
    cfg = configparser.ConfigParser()
    cfg.read(INI_PATH, encoding="utf-8")

    cached_ok = cfg.get("cache", "pages", fallback="false").strip().lower() == "true"
    try:
        pages_at = float(cfg.get("cache", "pages_at", fallback="0"))
    except ValueError:
        pages_at = 0.0

    # true 이고 TTL 이내 → 캐시 사용
    if cached_ok and (time.time() - pages_at < VERIFY_TTL):
        return True

    # false 이거나 TTL 만료 → 실제 확인
    ok = False
    try:
        r = requests.get(
            f"https://{gh_id}.github.io/{gh_repo}",
            timeout=6, allow_redirects=True,
        )
        ok = r.status_code < 400
    except Exception:
        pass

    if "cache" not in cfg:
        cfg["cache"] = {}
    cfg["cache"]["pages"]    = "true" if ok else "false"
    cfg["cache"]["pages_at"] = str(int(time.time()))
    _save_ini(cfg)
    return ok


GH_ID, GH_REPO, GH_BRANCH, FORCE_LOCAL = _load_ini()


def _read_dev_mode() -> bool:
    cfg = configparser.ConfigParser()
    cfg.read(INI_PATH, encoding="utf-8")
    return cfg.get("github", "local", fallback="0").strip() == "1"

DEV_MODE = _read_dev_mode()


def _gh_pem_url() -> str:
    if not (GH_ID and GH_REPO):
        return ""
    return f"https://raw.githubusercontent.com/{GH_ID}/{GH_REPO}/{GH_BRANCH}/public.pem"


def _gh_sig_url(h: str) -> str:
    if not (GH_ID and GH_REPO):
        return ""
    return f"https://raw.githubusercontent.com/{GH_ID}/{GH_REPO}/{GH_BRANCH}/Filesig/{h}.sig"


# ── 색상 ──────────────────────────────────────────────────
BG      = "#111111"
BG2     = "#1a1a1a"
BG3     = "#222222"
BORDER  = "#333333"
FG      = "#cccccc"
FG_DIM  = "#555555"
FG_OK   = "#55aa55"
FG_ERR  = "#aa5555"
FONT    = ("Courier New", 10)
FONT_SM = ("Courier New", 9)


# ── 공통 위젯 ─────────────────────────────────────────────
class FlatButton(tk.Button):
    def __init__(self, master, **kw):
        kw.setdefault("font", FONT)
        kw.setdefault("bg", BG2)
        kw.setdefault("fg", "#666666")
        kw.setdefault("activebackground", BG3)
        kw.setdefault("activeforeground", "#ffffff")
        kw.setdefault("relief", tk.FLAT)
        kw.setdefault("bd", 1)
        kw.setdefault("highlightbackground", BORDER)
        kw.setdefault("highlightthickness", 1)
        kw.setdefault("padx", 12)
        kw.setdefault("pady", 6)
        kw.setdefault("cursor", "hand2")
        super().__init__(master, **kw)


class DropZone(tk.Frame):
    """클릭 또는 드래그 & 드롭으로 파일 선택"""

    def __init__(self, master, label="파일을 드래그하거나 클릭하세요",
                 filetypes=None, callback=None, **kw):
        super().__init__(master, bg=BG, highlightbackground=BORDER,
                         highlightthickness=1, **kw)
        self._cb        = callback
        self._filetypes = filetypes or [("모든 파일", "*.*")]
        self._path      = None

        self._hint = tk.Label(self, text=label, font=FONT_SM, bg=BG, fg=FG_DIM)
        self._hint.pack(pady=4)
        self._name = tk.Label(self, text="—", font=FONT, bg=BG, fg=FG)
        self._name.pack(pady=(0, 4))

        for w in (self, self._hint, self._name):
            w.bind("<Button-1>", self._click)
            w.bind("<Enter>",    lambda e: self.config(highlightbackground="#666"))
            w.bind("<Leave>",    lambda e: self.config(highlightbackground=BORDER))

        try:
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._drop)
        except Exception:
            pass

    def _drop(self, event):
        path = event.data.strip().strip("{}")
        self._set(path)

    def _click(self, _=None):
        from tkinter import filedialog
        path = filedialog.askopenfilename(filetypes=self._filetypes)
        if path:
            self._set(path)

    def _set(self, path):
        self._path = path
        self._name.config(text=os.path.basename(path), fg=FG)
        if self._cb:
            self._cb(path)

    def get(self):    return self._path

    def clear(self):
        self._path = None
        self._name.config(text="—", fg=FG)


class StatusLabel(tk.Label):
    def __init__(self, master, **kw):
        kw.setdefault("font", FONT_SM)
        kw.setdefault("bg", BG)
        kw.setdefault("fg", FG_DIM)
        kw.setdefault("anchor", "w")
        kw.setdefault("justify", "left")
        kw.setdefault("wraplength", 400)
        kw.setdefault("text", "")
        super().__init__(master, **kw)

    def ok(self, msg):  self.config(text=msg, fg=FG_OK)
    def err(self, msg): self.config(text=msg, fg=FG_ERR)
    def dim(self, msg): self.config(text=msg, fg=FG_DIM)
    def clear(self):    self.config(text="")


# ── 공개키 캐시 ───────────────────────────────────────────
# 세션 메모리 캐시 (재시작 전까지 유지)
_cached_pub_key: "RSAPublicKey | None" = None
_cached_pub_mode: "bool | None" = None
_pub_key_lock = threading.Lock()


def _load_pub_cache() -> "bytes | None":
    """파일 캐시에서 공개키 바이트 반환. 없거나 TTL 만료면 None."""
    import time
    if not os.path.isfile(PUB_CACHE):
        return None
    if time.time() - os.path.getmtime(PUB_CACHE) > PUB_CACHE_TTL:
        return None
    with open(PUB_CACHE, "rb") as f:
        return f.read()


def _save_pub_cache(data: bytes) -> None:
    """공개키 바이트를 파일 캐시에 저장."""
    with open(PUB_CACHE, "wb") as f:
        f.write(data)


def get_pub_key(local_mode: bool) -> "RSAPublicKey":
    global _cached_pub_key, _cached_pub_mode
    with _pub_key_lock:
        if _cached_pub_key is not None and _cached_pub_mode == local_mode:
            return _cached_pub_key

        if local_mode:
            if not os.path.isfile(LOCAL_PUB):
                raise RuntimeError(f"로컬 모드: public.pem 없음\n({LOCAL_PUB})")
            with open(LOCAL_PUB, "rb") as f:
                pem_bytes = f.read()
        else:
            # 1순위: 파일 캐시 (TTL 이내)
            pem_bytes = _load_pub_cache()
            if pem_bytes is None:
                # 2순위: GitHub에서 다운로드 후 캐시 저장
                url = _gh_pem_url()
                if not url:
                    raise RuntimeError(f"ini에 url이 설정되지 않았습니다\n({INI_PATH})")
                r = requests.get(url, timeout=10)
                if r.status_code != 200:
                    raise RuntimeError(f"public.pem 다운로드 실패 ({r.status_code})")
                pem_bytes = r.content
                _save_pub_cache(pem_bytes)

        _cached_pub_key  = serialization.load_pem_public_key(pem_bytes)
        _cached_pub_mode = local_mode
    return _cached_pub_key


# ── SHA-512 ───────────────────────────────────────────────
def sha512_file(path: str) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── 탭: 검증 ─────────────────────────────────────────────
class VerifyTab(tk.Frame):
    def __init__(self, master, local_var: tk.BooleanVar):
        super().__init__(master, bg=BG)
        self._local = local_var

        tk.Label(self, text="대상 파일", font=FONT_SM,
                 bg=BG, fg=FG_DIM, anchor="w").pack(fill="x", pady=(0, 4))
        self._dz = DropZone(self, callback=self._on_file)
        self._dz.pack(fill="x")

        self._status = StatusLabel(self)
        self._status.pack(fill="x", pady=(8, 0))
        self._set_hint()

        local_var.trace_add("write", lambda *_: self._set_hint())

    def _set_hint(self):
        if self._local.get():
            self._status.dim("로컬 모드 — Filesig/ 와 public.pem 참조")
        elif GH_ID and GH_REPO:
            self._status.dim(f"GitHub ({GH_ID}/{GH_REPO}) 에서 서명 검증")

    def _on_file(self, path):
        self._status.dim("처리 중...")
        threading.Thread(
            target=self._verify, args=(path, self._local.get()), daemon=True
        ).start()

    def _verify(self, path: str, local_mode: bool):
        try:
            h   = sha512_file(path)
            pub = get_pub_key(local_mode)

            if local_mode:
                sig_path = os.path.join(LOCAL_FILESIG, h + ".sig")
                if not os.path.isfile(sig_path):
                    raise RuntimeError("서명 파일 없음")
                with open(sig_path, "rb") as f:
                    sig = f.read()
            else:
                url = _gh_sig_url(h)
                if not url:
                    raise RuntimeError(
                        f"ini에 url이 설정되지 않았습니다\n({INI_PATH})")
                r = requests.get(url, timeout=10)
                if r.status_code != 200:
                    raise RuntimeError(f"서명 파일 없음 — 미서명 파일입니다\n({h[:16]}…)")
                sig = r.content

            with open(path, "rb") as f:
                data = f.read()

            pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA512())
            self.after(0, self._status.ok, "✓ 서명 유효")

        except InvalidSignature:
            self.after(0, self._status.err, "✗ 서명 무효")
        except Exception as e:
            self.after(0, self._status.err, str(e))


# ── 탭: 서명 ─────────────────────────────────────────────
class SignTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self._key: RSAPrivateKey | None = None

        # 로컬 private.pem 자동 감지
        if os.path.isfile(LOCAL_PRIV):
            try:
                with open(LOCAL_PRIV, "rb") as f:
                    data = f.read()
                if b"PRIVATE KEY" not in data:
                    raise ValueError("PRIVATE KEY 헤더 없음")
                self._key = serialization.load_pem_private_key(data, password=None)
            except Exception:
                self._key = None

        # 개인키 폼 — 로컬 키 없을 때만 표시
        if self._key is None:
            self._pem_frame = tk.Frame(self, bg=BG)
            self._pem_frame.pack(fill="x", pady=(0, 12))
            tk.Label(self._pem_frame, text="개인키 (private.pem)", font=FONT_SM,
                     bg=BG, fg=FG_DIM, anchor="w").pack(fill="x", pady=(0, 4))
            self._pem_dz = DropZone(self._pem_frame,
                                    label="private.pem",
                                    filetypes=[("PEM 파일", "*.pem")],
                                    callback=self._load_key)
            self._pem_dz.pack(fill="x")
            self._pem_status = StatusLabel(self._pem_frame)
            self._pem_status.pack(fill="x", pady=(4, 0))
        else:
            self._pem_frame = None

        # 대상 파일
        tk.Label(self, text="대상 파일", font=FONT_SM,
                 bg=BG, fg=FG_DIM, anchor="w").pack(fill="x", pady=(0, 4))
        self._file_dz = DropZone(self, callback=self._try_sign)
        self._file_dz.pack(fill="x")

        self._status = StatusLabel(self)
        self._status.pack(fill="x", pady=(8, 0))

        if self._key is not None:
            self._status.dim("로컬 private.pem 로드됨 — 파일을 드래그하세요")

    def _load_key(self, path):
        self._key = None
        self._pem_status.clear()

        if os.path.basename(path) != "private.pem":
            self._pem_status.err(
                f"파일명이 private.pem이어야 합니다 (현재: {os.path.basename(path)})")
            self._pem_dz.clear()
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
            if b"PRIVATE KEY" not in data:
                raise ValueError("PRIVATE KEY 헤더 없음")
            self._key = serialization.load_pem_private_key(data, password=None)
        except Exception as e:
            self._pem_status.err(f"키 로드 실패: {e}")
            self._pem_dz.clear()
            return

        if self._pem_frame is not None:
            self._pem_frame.destroy()
            self._pem_frame = None
        self._try_sign(self._file_dz.get())

    def _try_sign(self, path):
        if not path:
            return
        if not self._key:
            from tkinter import messagebox
            if not messagebox.askyesno(
                "키 없음",
                "private.pem 이 없습니다.\n\n"
                "새 RSA-2048 키쌍을 자동 생성할까요?\n"
                "(public.pem 을 레포에 업로드해야 검증이 활성화됩니다)",
            ):
                self._status.dim("취소됨 — private.pem 을 먼저 준비하세요")
                return
            self._status.dim("키 생성 중...")
            threading.Thread(target=self._autogen_and_sign, args=(path,), daemon=True).start()
            return
        self._status.dim("처리 중...")
        threading.Thread(target=self._sign, args=(path,), daemon=True).start()

    def _autogen_and_sign(self, path):
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub  = priv.public_key()

            with open(LOCAL_PRIV, "wb") as f:
                f.write(priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
            with open(LOCAL_PUB, "wb") as f:
                f.write(pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))

            self._key = priv

            if getattr(self, "_pem_frame", None) is not None:
                self.after(0, self._pem_frame.destroy)
                self._pem_frame = None

            self.after(0, self._status.dim, "키 생성 완료 — 서명 중...")
            self._sign(path)
        except Exception as e:
            self.after(0, self._status.err, str(e))

    def _sign(self, path):
        try:
            h = sha512_file(path)
            with open(path, "rb") as f:
                data = f.read()
            sig = self._key.sign(data, padding.PKCS1v15(), hashes.SHA512())

            os.makedirs(LOCAL_FILESIG, exist_ok=True)
            out = os.path.join(LOCAL_FILESIG, h + ".sig")
            with open(out, "wb") as f:
                f.write(sig)

            self.after(0, self._status.ok, f"완료:\n{out}")
        except Exception as e:
            self.after(0, self._status.err, str(e))


# ── 탭: 키 생성 ──────────────────────────────────────────
class KeygenTab(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg=BG)
        self._priv = None
        self._pub  = None

        _keys_exist = os.path.isfile(LOCAL_PRIV) or os.path.isfile(LOCAL_PUB)

        frame = tk.Frame(self, bg=BG, highlightbackground=BORDER,
                         highlightthickness=1)
        frame.pack(fill="x", pady=4)

        inner = tk.Frame(frame, bg=BG, padx=16, pady=16)
        inner.pack(fill="x")

        row1 = tk.Frame(inner, bg=BG)
        row1.pack(anchor="w")

        self._gen_btn = FlatButton(row1, text="RSA-2048 키 생성",
                                   command=self._generate,
                                   state="disabled" if _keys_exist else "normal")
        self._gen_btn.pack(side="left", padx=(0, 8))

        self._chk_btn = FlatButton(row1, text="검사",
                                   command=self._check_keys)
        self._chk_btn.pack(side="left")

        self._status = StatusLabel(inner)
        self._status.pack(fill="x", pady=(12, 0))

        if _keys_exist:
            self._status.dim("키 파일 감지 — 검사 후 사용하세요")

    def _check_keys(self):
        self._status.dim("검사 중...")
        self._chk_btn.config(state="disabled")
        threading.Thread(target=self._do_check, daemon=True).start()

    def _do_check(self):
        has_priv = os.path.isfile(LOCAL_PRIV)
        has_pub  = os.path.isfile(LOCAL_PUB)

        try:
            if has_pub and not has_priv:
                self.after(0, self._status.dim, "개인키 없음 — 할 수 있는 게 없습니다")
                return

            if not has_priv:
                self.after(0, self._status.dim, "키 파일이 없습니다")
                return

            with open(LOCAL_PRIV, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            pub_from_priv = priv.public_key()

            if not has_pub:
                self._write_pub(pub_from_priv)
                self.after(0, self._status.ok, "public.pem 추출 완료")
                return

            with open(LOCAL_PUB, "rb") as f:
                pub_existing = serialization.load_pem_public_key(f.read())

            b_new = pub_from_priv.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            b_old = pub_existing.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            if b_new == b_old:
                self.after(0, self._status.ok, "키 일치 — 이상 없음")
            else:
                self._write_pub(pub_from_priv)
                self.after(0, self._status.ok, "불일치 — public.pem 덮어쓰기 완료")

        except Exception as e:
            self.after(0, self._status.err, str(e))
        finally:
            self.after(0, self._chk_btn.config, {"state": "normal"})
            keys_exist = os.path.isfile(LOCAL_PRIV) or os.path.isfile(LOCAL_PUB)
            self.after(0, self._gen_btn.config,
                       {"state": "disabled" if keys_exist else "normal"})

    def _write_pub(self, pub_key):
        pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(LOCAL_PUB, "wb") as f:
            f.write(pem)

    def _generate(self):
        self._status.dim("생성 중...")
        self._gen_btn.config(state="disabled")
        threading.Thread(target=self._do_gen, daemon=True).start()

    def _do_gen(self):
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub  = priv.public_key()

            with open(LOCAL_PRIV, "wb") as f:
                f.write(priv.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()))
            with open(LOCAL_PUB, "wb") as f:
                f.write(pub.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo))

            self.after(0, self._status.ok, "생성 완료 — private.pem / public.pem 저장됨")
            self.after(0, self._gen_btn.config, {"state": "disabled"})
        except Exception as e:
            self.after(0, self._status.err, str(e))
            self.after(0, self._gen_btn.config, {"state": "normal"})


# ── 메인 앱 ──────────────────────────────────────────────
class App(TkinterDnD.Tk):
    W, H = 480, 340

    def __init__(self):
        super().__init__()
        self.title("SigTool")
        self.configure(bg=BG)
        self.resizable(False, False)

        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        self.geometry(f"{self.W}x{self.H}+{(sw-self.W)//2}+{(sh-self.H)//2}")

        # ── 타이틀 행 ────────────────────────────────────
        title_row = tk.Frame(self, bg=BG)
        title_row.pack(fill="x", padx=24, pady=(20, 0))

        tk.Label(title_row, text="SigTool", font=("Courier New", 12, "bold"),
                 bg=BG, fg="#ffffff").pack(side="left")

        self._local_var = tk.BooleanVar(value=FORCE_LOCAL)
        if DEV_MODE:
            self._local_chk = tk.Checkbutton(
                title_row, text="로컬 모드", variable=self._local_var,
                font=FONT_SM, bg=BG, fg=FG_DIM,
                activebackground=BG, activeforeground=FG,
                selectcolor=BG3, relief=tk.FLAT, bd=0, cursor="hand2",
                state="disabled" if FORCE_LOCAL else "normal",
            )
            self._local_chk.pack(side="right", padx=(0, 2))

        if GH_ID and GH_REPO and not FORCE_LOCAL:
            self._add_link_buttons(title_row)

        # ── 탭 바 ────────────────────────────────────────
        tab_bar = tk.Frame(self, bg=BG, highlightbackground=BORDER,
                           highlightthickness=1)
        tab_bar.pack(fill="x", padx=24, pady=(12, 0))

        self._tab_btns = []
        self._panels   = []

        content = tk.Frame(self, bg=BG, padx=24, pady=16)
        content.pack(fill="both", expand=True)

        tabs = [
            ("검증", lambda p: VerifyTab(p, self._local_var)),
            ("서명", SignTab),
        ]
        if DEV_MODE:
            tabs.append(("키 생성", KeygenTab))

        for i, (label, factory) in enumerate(tabs):
            panel = factory(content)
            panel.place(relwidth=1, relheight=1)
            self._panels.append(panel)

            btn = tk.Button(tab_bar, text=label, font=FONT_SM,
                            bg=BG, fg="#666666", relief=tk.FLAT, bd=0,
                            padx=12, pady=6, cursor="hand2",
                            activebackground=BG3, activeforeground="#ffffff",
                            command=lambda idx=i: self._switch(idx))
            btn.pack(side="left")
            self._tab_btns.append(btn)

        self._switch(0)

    def _add_link_buttons(self, parent):
        import webbrowser
        gh_url    = f"https://github.com/{GH_ID}/{GH_REPO}"
        pages_url = f"https://{GH_ID}.github.io/{GH_REPO}"

        FlatButton(parent, text="깃허브",
                   command=lambda: webbrowser.open(gh_url)
                   ).pack(side="right", padx=(0, 4))

        threading.Thread(
            target=self._check_pages_async,
            args=(parent, pages_url),
            daemon=True,
        ).start()

    def _check_pages_async(self, parent, pages_url):
        import webbrowser
        if _check_pages(GH_ID, GH_REPO):
            self.after(0, lambda: FlatButton(
                parent, text="설명서",
                command=lambda: webbrowser.open(pages_url),
            ).pack(side="right", padx=(0, 4)))

    def _switch(self, idx):
        for i, (btn, panel) in enumerate(zip(self._tab_btns, self._panels)):
            if i == idx:
                btn.config(bg=BG3, fg="#ffffff")
                panel.lift()
            else:
                btn.config(bg=BG, fg="#666666")


if __name__ == "__main__":
    app = App()
    app.mainloop()
