# backend/models.py
from pydantic import BaseModel

class Record(BaseModel):
    record_id: str
    data: str
