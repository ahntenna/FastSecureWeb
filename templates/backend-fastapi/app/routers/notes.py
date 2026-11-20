"""예제 CRUD. 보안 채널(서명·암호화) 위에서 동작하는 엔드포인트의 본보기다.

인증은 포함하지 않았다. 사용자별 데이터를 다루게 되면 소유자 컬럼을 추가하고
조회·삭제 쿼리에 소유자 조건을 반드시 넣는다(남의 객체는 404).
"""
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import select

from app.deps import Db
from app.models import Note
from app.schemas import NoteCreate, NoteOut

router = APIRouter(prefix="/notes")


@router.get("", response_model=list[NoteOut])
def list_notes(
    db: Db,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> list[Note]:
    return list(db.scalars(select(Note).order_by(Note.id.desc()).limit(limit).offset(offset)))


@router.post("", response_model=NoteOut, status_code=201)
def create_note(body: NoteCreate, db: Db) -> Note:
    note = Note(title=body.title, body=body.body)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.delete("/{note_id}", status_code=204)
def delete_note(note_id: int, db: Db) -> Response:
    note = db.get(Note, note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="not found")
    db.delete(note)
    db.commit()
    return Response(status_code=204)
