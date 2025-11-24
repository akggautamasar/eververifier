import os
import tempfile
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import pyzipper
from lxml import etree
from rapidfuzz import fuzz
from dotenv import load_dotenv

load_dotenv()
app = FastAPI(title="EVER Aadhaar eKYC Verification (Render)")

# CORS - for testing allow all origins. Replace "*" with your Lovable domain in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MATCH_NAME_SCORE = float(os.getenv("MATCH_NAME_SCORE", "75.0"))
MAX_SHARECODE_ATTEMPTS = int(os.getenv("MAX_SHARECODE_ATTEMPTS", "5"))

def sha256(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

def decrypt_zip_get_xml(zip_path: str, share_code: str) -> bytes:
    """
    Decrypt AES-encrypted ZIP produced by UIDAI Offline e-KYC using the share_code.
    Returns XML bytes on success or raises ValueError on failure.
    """
    with pyzipper.AESZipFile(zip_path) as zf:
        xml_name = next((n for n in zf.namelist() if n.lower().endswith('.xml')), None)
        if not xml_name:
            raise ValueError("No XML file in ZIP")
        try:
            data = zf.read(xml_name, pwd=share_code.encode('utf-8'))
            return data
        except RuntimeError as e:
            raise ValueError("Unable to decrypt ZIP; wrong share code or corrupted file") from e

def parse_ekyc_xml(xml_bytes: bytes):
    """
    Lightweight XML parsing to extract common UIDAI fields.
    Adjust tag list if your XML has different paths.
    """
    root = etree.fromstring(xml_bytes)
    def find_text(names):
        for n in names:
            el = root.find('.//'+n)
            if el is not None and el.text:
                return el.text.strip()
        return None
    name = find_text(['Poi/Name','Name','Poi'])
    masked = find_text(['MaskedAadhaar','MaskedUid','MaskedAadhaarNumber'])
    return {"name": name, "masked": masked, "xml_bytes": xml_bytes}

@app.get("/ping")
def ping():
    return {"status": "ok"}

@app.post("/verify/ekyc")
async def verify_ekyc(
    request: Request,
    zip_file: UploadFile = File(...),
    share_code: str = Form(...),
    expected_name: str = Form(None),
    expected_last4: str = Form(None),
    verifier_email: str = Form(None),
):
    # Basic validations
    if not zip_file.filename.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail="Upload a ZIP file (.zip)")
    # Process in a temp dir and delete after
    with tempfile.TemporaryDirectory() as tmpdir:
        zpath = os.path.join(tmpdir, "upload.zip")
        contents = await zip_file.read()
        with open(zpath, "wb") as f:
            f.write(contents)
        file_hash = sha256(contents)
        # try decrypt and parse XML
        try:
            xml_bytes = decrypt_zip_get_xml(zpath, share_code)
        except Exception as e:
            return JSONResponse({"status":"failed","reason":str(e)}, status_code=400)
        parsed = parse_ekyc_xml(xml_bytes)
        name = parsed.get("name")
        masked = parsed.get("masked")
        # name fuzzy matching (if expected_name provided)
        name_score = 0.0
        if expected_name and name:
            name_score = fuzz.token_sort_ratio(expected_name.lower(), name.lower())
        # last4 check (if provided)
        last4_ok = False
        if expected_last4 and masked:
            digits = ''.join([c for c in masked if c.isdigit()])
            last4_ok = digits.endswith(expected_last4)
        # decision logic
        verified = False
        reason = ""
        if expected_name:
            if name_score >= MATCH_NAME_SCORE:
                verified = True
            else:
                reason = f"name_mismatch (score={name_score})"
        elif expected_last4:
            if last4_ok:
                verified = True
            else:
                reason = "last4_mismatch"
        else:
            # no hint provided -> accept decryption as weak verification
            verified = True
        resp = {
            "status": "verified" if verified else "low_confidence",
            "name_extracted": name,
            "masked_extracted": masked,
            "name_score": name_score,
            "file_hash": file_hash,
            "uploader_ip": request.client.host if request.client else None,
            "reason": reason
        }
        return JSONResponse(resp)
