import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.api.core_serializers import event_response
from app.db.dependencies import get_db
from app.models.user import User
from app.schemas.collector import CollectorStatusResponse, CollectorSubmitResponse
from app.services.collector import MAX_BATCH_EVENTS, collector_status, consume_rate_limit, submit_event

router = APIRouter(prefix="/collector", tags=["collector"])

# 20 events with 16 KB of raw data each, plus field overhead.
MAX_BODY_BYTES = 512 * 1024


def _reject_non_standard_number(value: str) -> None:
    raise ValueError(f"{value} is not valid JSON")


async def read_collector_body(request: Request) -> Any:
    """Read the JSON body with a size cap and without FastAPI validation, whose errors echo input."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body is too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="Request body is too large")
    try:
        return json.loads(body, parse_constant=_reject_non_standard_number)
    except RecursionError:
        # Deeply nested JSON exhausts the parser's recursion limit; answer safely instead of 500.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Request body is nested too deeply"
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Request body must be valid JSON"
        ) from None


@router.post("/events", response_model=CollectorSubmitResponse)
def submit_collector_events(
    # Authentication resolves first, so unauthenticated bodies are never read.
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    body: Annotated[Any, Depends(read_collector_body)],
) -> CollectorSubmitResponse:
    events = body.get("events") if isinstance(body, dict) else None
    if not isinstance(events, list) or not events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Body must be an object with a non-empty 'events' array",
        )
    if len(events) > MAX_BATCH_EVENTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"A batch may contain at most {MAX_BATCH_EVENTS} events",
        )
    consume_rate_limit(current_user, len(events))

    results = [submit_event(db, current_user, index, event) for index, event in enumerate(events)]
    return CollectorSubmitResponse(
        created=sum(result.status == "created" for result in results),
        duplicates=sum(result.status == "duplicate" for result in results),
        rejected=sum(result.status == "rejected" for result in results),
        results=results,
    )


@router.get("/status", response_model=CollectorStatusResponse)
def get_collector_status(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(get_current_user)],
) -> CollectorStatusResponse:
    summary = collector_status(db)
    return CollectorStatusResponse(
        **{**summary, "recent_events": [event_response(event) for event in summary["recent_events"]]}
    )
