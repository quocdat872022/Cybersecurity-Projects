"""
©AngelaMos | 2026
test_review.py

Tests analyst review endpoints and the review queue query
"""

import uuid
from datetime import datetime, UTC

import pytest

from app.models.threat_event import ThreatEvent
from app.services import threat_service


def _make_event(severity: str = "MEDIUM", reviewed: bool = False) -> ThreatEvent:
    return ThreatEvent(
        id=uuid.uuid4(),
        created_at=datetime.now(UTC),
        source_ip="10.0.0.5",
        request_method="GET",
        request_path="/api/search",
        status_code=200,
        response_size=512,
        user_agent="Mozilla/5.0",
        threat_score=0.6,
        severity=severity,
        component_scores={"RATE_ANOMALY": 0.3},
        feature_vector=[0.0] * 35,
        matched_rules=["RATE_ANOMALY"],
        reviewed=reviewed,
    )


@pytest.mark.asyncio
async def test_mark_reviewed_sets_label(db_session) -> None:
    event = _make_event()
    db_session.add(event)
    await db_session.commit()

    result = await threat_service.mark_reviewed(
        db_session, event.id, "true_positive"
    )

    assert result is not None
    assert result.reviewed is True
    assert result.review_label == "true_positive"


@pytest.mark.asyncio
async def test_mark_reviewed_missing_returns_none(db_session) -> None:
    result = await threat_service.mark_reviewed(
        db_session, uuid.uuid4(), "false_positive"
    )
    assert result is None


@pytest.mark.asyncio
async def test_review_queue_only_unreviewed_medium(db_session) -> None:
    medium_unreviewed = _make_event(severity="MEDIUM", reviewed=False)
    medium_reviewed = _make_event(severity="MEDIUM", reviewed=True)
    high_unreviewed = _make_event(severity="HIGH", reviewed=False)

    db_session.add_all([medium_unreviewed, medium_reviewed, high_unreviewed])
    await db_session.commit()

    queue = await threat_service.get_review_queue(db_session)

    ids = {item.id for item in queue}
    assert medium_unreviewed.id in ids
    assert medium_reviewed.id not in ids
    assert high_unreviewed.id not in ids


@pytest.mark.asyncio
async def test_review_endpoint_patch(db_session, db_client) -> None:
    event = _make_event()
    db_session.add(event)
    await db_session.commit()

    response = await db_client.patch(
        f"/threats/{event.id}/review",
        json={"label": "true_positive"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["reviewed"] is True
    assert data["review_label"] == "true_positive"


@pytest.mark.asyncio
async def test_review_endpoint_invalid_label(db_session, db_client) -> None:
    event = _make_event()
    db_session.add(event)
    await db_session.commit()

    response = await db_client.patch(
        f"/threats/{event.id}/review",
        json={"label": "not_a_real_label"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_review_queue_endpoint(db_session, db_client) -> None:
    event = _make_event(severity="MEDIUM", reviewed=False)
    db_session.add(event)
    await db_session.commit()

    response = await db_client.get("/threats/review-queue")

    assert response.status_code == 200
    data = response.json()
    assert any(item["id"] == str(event.id) for item in data)