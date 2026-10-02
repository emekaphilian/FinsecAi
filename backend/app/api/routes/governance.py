"""Tenant scoped governance source document management."""
from datetime import datetime
from pathlib import Path
import re
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pypdf import PdfReader
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.authorization import is_platform_owner, resolve_tenant_context
from app.db.models import GovernanceControl, GovernanceDocument, User
from app.db.session import get_db

router = APIRouter(prefix="/governance", tags=["governance"])
MAX_DOCUMENT_BYTES = 15 * 1024 * 1024
DOCUMENT_DIR = Path(__file__).resolve().parents[3] / "tmp" / "governance_documents"


def _serialize(document: GovernanceDocument, controls: list[GovernanceControl] | None = None):
    return {
        "id": document.id, "tenant_id": document.tenant_id,
        "document_type": document.document_type, "name": document.name,
        "version": document.version, "issuer": document.issuer,
        "effective_date": document.effective_date.isoformat() if document.effective_date else None,
        "source": document.source, "status": document.status,
        "created_at": document.created_at.isoformat() if document.created_at else None,
        "controls": [{
            "id": c.id, "control_id": c.control_id, "title": c.title,
            "control_text": c.control_text, "status": (c.metadata_json or {}).get("review_status", "PENDING"),
            "metadata": c.metadata_json or {},
        } for c in (controls or [])],
    }


def _tenant_scope(db: Session, user: User, tenant_id: str | None) -> str:
    context = resolve_tenant_context(db, user, tenant_id)
    if not context.tenant_id:
        raise HTTPException(400, "Select a tenant workspace to manage governance documents.")
    return context.tenant_id


@router.get("/documents")
def list_documents(tenant_id: str | None = None, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scoped_tenant = _tenant_scope(db, user, tenant_id)
    docs = db.scalars(select(GovernanceDocument).where(or_(
        GovernanceDocument.tenant_id == scoped_tenant, GovernanceDocument.tenant_id.is_(None)
    )).order_by(GovernanceDocument.created_at.desc())).all()
    return [_serialize(doc, db.scalars(select(GovernanceControl).where(
        GovernanceControl.governance_document_id == doc.id
    )).all()) for doc in docs]


@router.post("/documents/upload")
async def upload_document(
    document_type: str = Form(...), name: str = Form(...), version: str = Form(...),
    issuer: str = Form(""), effective_date: str = Form(""), tenant_id: str | None = Form(None),
    file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user),
):
    if user.role not in {"admin", "owner"}:
        raise HTTPException(403, "Tenant administrator permission required.")
    if document_type not in {"POLICY", "REGULATION", "FRAMEWORK"}:
        raise HTTPException(400, "Unsupported governance document type.")
    if is_platform_owner(user) and document_type == "REGULATION" and not tenant_id:
        scoped_tenant = None
    else:
        scoped_tenant = _tenant_scope(db, user, tenant_id)
    raw = await file.read(MAX_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise HTTPException(413, "Document exceeds the 15 MB upload limit.")
    filename = Path(file.filename or "").name
    if not filename.lower().endswith((".pdf", ".txt")):
        raise HTTPException(400, "Upload a PDF or plain text policy document.")
    try:
        if filename.lower().endswith(".pdf"):
            import io
            extracted = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages)
        else:
            extracted = raw.decode("utf-8-sig")
    except Exception as exc:
        raise HTTPException(400, "Could not read the uploaded document.") from exc
    if not extracted.strip():
        raise HTTPException(400, "No selectable text found. Upload a text based PDF or TXT document.")

    DOCUMENT_DIR.mkdir(parents=True, exist_ok=True)
    stored_name = f"{uuid.uuid4().hex}{Path(filename).suffix.lower()}"
    (DOCUMENT_DIR / stored_name).write_bytes(raw)
    try:
        effective = datetime.fromisoformat(effective_date) if effective_date else None
    except ValueError as exc:
        (DOCUMENT_DIR / stored_name).unlink(missing_ok=True)
        raise HTTPException(400, "Effective date must be ISO format, such as 2026-09-01.") from exc
    try:
        doc = GovernanceDocument(
            tenant_id=scoped_tenant, document_type=document_type, name=name.strip(), version=version.strip(),
            issuer=issuer.strip(), effective_date=effective, source=stored_name, status="ACTIVE",
            metadata_json={"original_filename": filename, "extracted_text": extracted, "review_status": "REVIEW_REQUIRED"},
        )
        db.add(doc)
        db.flush()
        # Create reviewable candidate clauses. None enter matching until an admin approves them.
        clauses = [re.sub(r"\s+", " ", item).strip(" -•\t") for item in re.split(r"(?<=[.;])\s+|\n+", extracted)]
        clauses = [item for item in clauses if len(item) >= 45][:250]
        for index, clause in enumerate(clauses, 1):
            db.add(GovernanceControl(
                governance_document_id=doc.id, control_id=f"{document_type[:3]}-{index:03d}",
                title=clause[:120], control_text=clause,
                control_type="REGULATORY_REQUIREMENT" if document_type == "REGULATION" else "POLICY_REQUIREMENT",
                metadata_json={"review_status": "PENDING", "source_page": None},
            ))
        db.commit()
    except Exception:
        db.rollback()
        (DOCUMENT_DIR / stored_name).unlink(missing_ok=True)
        raise
    db.refresh(doc)
    controls = db.scalars(select(GovernanceControl).where(GovernanceControl.governance_document_id == doc.id)).all()
    return _serialize(doc, controls)


@router.post("/controls/{control_id}/review")
def review_control(control_id: str, approved: bool, tenant_id: str | None = None,
                   db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role not in {"admin", "owner"}:
        raise HTTPException(403, "Tenant administrator permission required.")
    control = db.get(GovernanceControl, control_id)
    document = db.get(GovernanceDocument, control.governance_document_id) if control else None
    if not control or not document:
        raise HTTPException(404, "Governance control not found.")
    if document.tenant_id is None:
        if not is_platform_owner(user):
            raise HTTPException(404, "Governance control not found.")
    elif document.tenant_id != _tenant_scope(db, user, tenant_id):
        raise HTTPException(404, "Governance control not found.")
    metadata = dict(control.metadata_json or {})
    metadata["review_status"] = "APPROVED" if approved else "REJECTED"
    metadata["reviewed_by"] = user.id
    metadata["reviewed_at"] = datetime.utcnow().isoformat()
    control.metadata_json = metadata
    db.commit()
    return {"control_id": control.id, "status": metadata["review_status"]}


@router.get("/documents/{document_id}/file")
def download_document(document_id: str, tenant_id: str | None = None,
                      db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    document = db.get(GovernanceDocument, document_id)
    if document is None:
        raise HTTPException(404, "Governance document not found.")
    if document.tenant_id is None:
        if not is_platform_owner(user):
            raise HTTPException(404, "Governance document not found.")
    elif document.tenant_id != _tenant_scope(db, user, tenant_id):
        raise HTTPException(404, "Governance document not found.")
    path = DOCUMENT_DIR / Path(document.source).name
    if not path.is_file():
        raise HTTPException(404, "The stored source file is unavailable.")
    return FileResponse(path, filename=(document.metadata_json or {}).get("original_filename", document.name))
