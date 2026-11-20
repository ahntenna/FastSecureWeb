"""요청·응답 스키마. 정의하지 않은 필드는 거부한다(extra="forbid")."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoteCreate(StrictModel):
    title: str = Field(min_length=1, max_length=100)
    body: str = Field(default="", max_length=4000)


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    body: str
    created_at: datetime


class HandshakeIn(StrictModel):
    # P-256 비압축 점 65바이트의 base64url = 87자
    pub: str = Field(min_length=87, max_length=87)


class HandshakeOut(BaseModel):
    pub: str
    salt: str
    sig: str
    ts: int


GuardSignal = Literal[
    "devtools-size", "devtools-timing", "devtools-console", "debugger-tamper", "automation"
]


class GuardReport(StrictModel):
    signal: GuardSignal
    path: str = Field(default="", max_length=200)


class GuardAction(BaseModel):
    action: Literal["none", "block"]
