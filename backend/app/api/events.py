from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.schemas import EventCreate, Event as EventSchema
from app.models.database import Event as EventDB
from app.services.event_service import EventService, EventBatch
from app.config import settings

router = APIRouter()

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True

@router.post("")  # POST /api/v1/events
async def create_event(
    event: EventCreate,
    api_key_valid: bool = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Submit a security event to MiniSOC."""
    service = EventService(db)
    result = service.process_event(event)

    return {
        "status": "success",
        "event_id": result["event"]["id"],
        "alerts_created": result["alerts_created"],
        "incidents": result["incidents"]
    }

@router.get("")  # GET /api/v1/events
async def list_events(
    limit: int = 100,
    db: Session = Depends(get_db)
):
    """List recent events."""
    events = db.query(EventDB).order_by(EventDB.timestamp.desc()).limit(limit).all()
    return [EventSchema.model_validate(e) for e in events]

@router.post("/batch", response_model=dict)
async def create_events_batch(
    batch: EventBatch,
    api_key_valid: bool = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    """Submit multiple events at once."""
    service = EventService(db)
    return service.process_batch(batch)