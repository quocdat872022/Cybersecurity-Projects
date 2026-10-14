"""
©AngelaMos | 2026
test_active_learning.py

Tests the LabelWatcher active-learning trigger logic
"""

import uuid
from datetime import datetime, UTC
from unittest import mock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from app.core.active_learning import LabelWatcher
from app.models.threat_event import ThreatEvent
from app.models.training_state import TrainingState


@pytest.fixture
async def session_factory():
    from app.models import model_metadata as _a, threat_event as _b, training_state as _c  # noqa: F401
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _reviewed_event() -> ThreatEvent:
    return ThreatEvent(
        id=uuid.uuid4(),
        created_at=datetime.now(UTC),
        source_ip="10.0.0.1",
        request_method="GET",
        request_path="/x",
        status_code=200,
        response_size=1,
        user_agent="x",
        threat_score=0.6,
        severity="MEDIUM",
        component_scores={},
        feature_vector=[0.0] * 35,
        reviewed=True,
        review_label="true_positive",
    )


@pytest.mark.asyncio
async def test_no_trigger_below_threshold(session_factory) -> None:
    async with session_factory() as session:
        for _ in range(5):
            session.add(_reviewed_event())
        await session.commit()

    watcher = LabelWatcher(session_factory, label_threshold=50)

    with mock.patch(
        "app.api.models_api._retrain_from_db", new_callable=mock.AsyncMock
    ) as mock_retrain:
        await watcher._check_and_trigger()
        mock_retrain.assert_not_called()


@pytest.mark.asyncio
async def test_triggers_at_threshold(session_factory) -> None:
    async with session_factory() as session:
        for _ in range(10):
            session.add(_reviewed_event())
        await session.commit()

    watcher = LabelWatcher(session_factory, label_threshold=10)

    with mock.patch(
        "app.api.models_api._retrain_from_db", new_callable=mock.AsyncMock
    ) as mock_retrain:
        await watcher._check_and_trigger()
        mock_retrain.assert_called_once()

    async with session_factory() as session:
        state = await session.get(TrainingState, 1)
        assert state.labels_since_last_train == 10
        assert state.last_retrain_at is not None


@pytest.mark.asyncio
async def test_does_not_retrigger_on_same_count(session_factory) -> None:
    async with session_factory() as session:
        for _ in range(10):
            session.add(_reviewed_event())
        await session.commit()

    watcher = LabelWatcher(session_factory, label_threshold=10)

    with mock.patch(
        "app.api.models_api._retrain_from_db", new_callable=mock.AsyncMock
    ) as mock_retrain:
        await watcher._check_and_trigger()
        await watcher._check_and_trigger()
        assert mock_retrain.call_count == 1