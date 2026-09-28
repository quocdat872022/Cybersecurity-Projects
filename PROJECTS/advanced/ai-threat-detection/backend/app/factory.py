"""
©AngelaMos | 2026
factory.py

FastAPI application factory with async lifespan managing
database, Redis, pipeline, and ML model initialization

lifespan creates the async SQLAlchemy engine and session
factory, runs SQLModel.metadata.create_all, connects
Redis, initializes GeoIPService, constructs the Alert
Dispatcher, attempts to load the ONNX InferenceEngine
(falling back to rules-only mode), builds the Pipeline
with configured queue sizes and ensemble weights, starts
the LogTailer if the nginx log directory exists, and
stores all components on app.state. On shutdown it stops
the tailer, pipeline, GeoIP, Redis, and disposes the DB
engine. _load_inference_engine lazily imports onnxruntime
-backed InferenceEngine, returning None if the dependency
is missing or no models exist. create_app assembles the
FastAPI instance and mounts all six API routers (health,
ingest, threats, stats, models, websocket)

Connects to:
  config.py               - settings for all config values
  core/ingestion/pipeline - Pipeline
  core/ingestion/tailer   - LogTailer
  core/detection/rules    - RuleEngine
  core/detection/inference- InferenceEngine (optional)
  core/alerts/dispatcher  - AlertDispatcher
  core/enrichment/geoip   - GeoIPService
  core/redis_manager      - redis_manager
  api/                    - all route modules
  models/                 - SQLModel registration
"""

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

from app.config import settings
from app.core.alerts.dispatcher import AlertDispatcher
from app.core.detection.rules import RuleEngine
from app.core.enrichment.geoip import GeoIPService
from app.core.ingestion.pipeline import Pipeline
from app.core.ingestion.tailer import LogTailer
from app.core.redis_manager import redis_manager
from app.models import model_metadata as _model_metadata_reg  # noqa: F401
from app.models import threat_event as _threat_event_reg  # noqa: F401
from app.core.active_learning import LabelWatcher
from app.core.enrichment.correlator import EventCorrelator
from app.core.ingestion.error_pipeline import ErrorAnalysisResult, ErrorLogPipeline
from app.core.ingestion.error_tailer import DualLogTailer
if TYPE_CHECKING:
    from app.core.detection.inference import InferenceEngine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application startup and shutdown lifecycle.
    """
    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    engine = create_async_engine(settings.database_url)
    app.state.db_engine = engine
    app.state.session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    logger.info("Database tables verified")

    await redis_manager.connect()

    geoip = GeoIPService(settings.geoip_db_path)

    redis_client = redis_manager.client
    assert redis_client is not None

    dispatcher = AlertDispatcher(
        redis_client=redis_client,
        session_factory=app.state.session_factory,
    )

    inference_engine = _load_inference_engine()
    app.state.models_loaded = inference_engine is not None and inference_engine.is_loaded
    app.state.detection_mode = "hybrid" if app.state.models_loaded else "rules"

    pipeline = Pipeline(
        redis_client=redis_client,
        rule_engine=RuleEngine(),
        geoip=geoip,
        on_result=dispatcher.dispatch,
        inference_engine=inference_engine,
        ensemble_weights={
            "ae": settings.ensemble_weight_ae,
            "rf": settings.ensemble_weight_rf,
            "if": settings.ensemble_weight_if,
        },
        raw_queue_size=settings.raw_queue_size,
        parsed_queue_size=settings.parsed_queue_size,
        feature_queue_size=settings.feature_queue_size,
        alert_queue_size=settings.alert_queue_size,
    )
    correlator = EventCorrelator()
    pipeline._on_parsed = correlator.record_access 

    await pipeline.start()

    label_watcher = LabelWatcher(app.state.session_factory)
    label_watcher.start()
    app.state.label_watcher = label_watcher

    tailer = None
    error_pipeline = None
    log_dir = Path(settings.nginx_log_path).resolve().parent
    error_log_path = str(Path(settings.nginx_log_path).with_name("error.log"))

    if log_dir.is_dir():
        loop = asyncio.get_running_loop()
        access_position_path = Path(settings.model_dir) / ".tailer_pos.json"

        if Path(error_log_path).parent.is_dir():
            error_queue: asyncio.Queue[str | None] = asyncio.Queue(maxsize=500)

            async def _log_error_analysis(result: ErrorAnalysisResult) -> None:
                access_ctx = ""
                if result.correlated.access is not None:
                    access_ctx = (
                        f" correlated_path={result.correlated.access.path}"
                        f" correlated_ip={result.correlated.access.ip}"
                        f" delta_s={result.correlated.time_delta_seconds:.2f}"
                    )
                logger.info(
                    "error_event level=%s client_ip=%s body_entropy=%.2f "
                    "body_attack_pattern=%s%s",
                    result.error.level,
                    result.error.client_ip,
                    result.body_features["body_entropy"],
                    result.body_features["body_has_attack_pattern"],
                    access_ctx,
                )

            error_pipeline = ErrorLogPipeline(
                error_queue=error_queue,
                correlator=correlator,
                on_result=_log_error_analysis,
            )
            await error_pipeline.start()

            error_position_path = Path(settings.model_dir) / ".error_tailer_pos.json"
            tailer = DualLogTailer(
                access_log_path=settings.nginx_log_path,
                error_log_path=error_log_path,
                access_queue=pipeline.raw_queue,
                error_queue=error_queue,
                loop=loop,
                access_position_path=access_position_path,
                error_position_path=error_position_path,
            )
        else:
            tailer = LogTailer(
                settings.nginx_log_path,
                pipeline.raw_queue,
                loop,
                position_path=access_position_path,
            )
        tailer.start()
    else:
        logger.warning("Log directory %s not found — tailer disabled", log_dir)

    app.state.pipeline = pipeline
    app.state.tailer = tailer
    app.state.geoip = geoip
    app.state.pipeline_running = True
    app.state.error_pipeline = error_pipeline

    logger.info("AngelusVigil started — pipeline active")

    yield

    app.state.pipeline_running = False
    if tailer is not None:
        tailer.stop()
    await app.state.label_watcher.stop()
    await pipeline.stop()
    if error_pipeline is not None:
        await error_pipeline.stop()
    geoip.close()
    await redis_manager.disconnect()
    await engine.dispose()

    logger.info("AngelusVigil shut down cleanly")


def _load_inference_engine() -> InferenceEngine | None:
    """
    Attempt to load the ONNX inference engine from the
    configured model directory, returning None if ML
    dependencies are missing or no models are found
    """
    try:
        from app.core.detection.inference import (
            InferenceEngine, )
    except ImportError:
        logger.info("onnxruntime not installed — running in rules-only mode")
        return None

    engine = InferenceEngine(model_dir=settings.model_dir)
    if engine.is_loaded:
        logger.info(
            "ML models loaded from %s",
            settings.model_dir,
        )
        return engine

    logger.info(
        "No ML models found in %s — running in rules-only mode",
        settings.model_dir,
    )
    return None


def create_app() -> FastAPI:
    """
    Build and configure the AngelusVigil FastAPI application.
    """
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.startup_time = time.monotonic()
    app.state.pipeline_running = False

    from app.api.health import router as health_router
    from app.api.ingest import router as ingest_router
    from app.api.models_api import router as models_router
    from app.api.stats import router as stats_router
    from app.api.threats import router as threats_router
    from app.api.websocket import router as ws_router

    app.include_router(health_router)
    app.include_router(ingest_router)
    app.include_router(threats_router)
    app.include_router(stats_router)
    app.include_router(models_router)
    app.include_router(ws_router)

    return app
