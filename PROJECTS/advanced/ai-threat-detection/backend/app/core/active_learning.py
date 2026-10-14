"""
©AngelaMos | 2026
active_learning.py

Background task that watches for newly reviewed threat
events and automatically triggers retraining once enough
analyst labels have accumulated.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.threat_event import ThreatEvent
from app.models.training_state import TrainingState

logger = logging.getLogger(__name__)

DEFAULT_LABEL_THRESHOLD = 50
DEFAULT_POLL_INTERVAL = 60.0


class LabelWatcher:
    """
    Polls for newly reviewed threat events; triggers retraining
    once the accumulated label count crosses a threshold.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        label_threshold: int = DEFAULT_LABEL_THRESHOLD,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._session_factory = session_factory
        self._threshold = label_threshold
        self._interval = poll_interval_seconds
        self._task: asyncio.Task[None] | None = None
        self._stopped = False

    def start(self) -> None:
        self._stopped = False
        self._task = asyncio.create_task(self._run(), name="label-watcher")
        logger.info(
            "LabelWatcher started — threshold=%d interval=%.0fs",
            self._threshold, self._interval,
        )

    async def stop(self) -> None:
        self._stopped = True
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("LabelWatcher stopped")

    async def _run(self) -> None:
        while not self._stopped:
            try:
                await asyncio.sleep(self._interval)
                await self._check_and_trigger()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("LabelWatcher iteration failed")

    async def _get_or_create_state(self, session: AsyncSession) -> TrainingState:
        state = await session.get(TrainingState, 1)
        if state is None:
            state = TrainingState(id=1)
            session.add(state)
            await session.commit()
            await session.refresh(state)
        return state

    async def _check_and_trigger(self) -> None:
        async with self._session_factory() as session:
            state = await self._get_or_create_state(session)
            reviewed_count = (await session.execute(
                select(func.count()).select_from(ThreatEvent).where(
                    ThreatEvent.reviewed == True  # noqa: E712  # type: ignore[arg-type]
                )
            )).scalar_one()

            new_labels = reviewed_count - state.labels_since_last_train
            if new_labels < self._threshold:
                return

            logger.info(
                "LabelWatcher: %d new labels (>= %d) — triggering retrain",
                new_labels, self._threshold,
            )

        # Import here to avoid a circular import with api/models_api.py
        from app.api.models_api import _retrain_from_db

        await _retrain_from_db(uuid.uuid4().hex, self._session_factory)

        async with self._session_factory() as session:
            state = await self._get_or_create_state(session)
            state.labels_since_last_train = reviewed_count
            state.last_retrain_at = datetime.now(UTC)
            session.add(state)
            await session.commit()