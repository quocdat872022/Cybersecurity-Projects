"""
©AngelaMos | 2026
training_state.py

Singleton table tracking active-learning label accumulation
between training runs.
"""

from datetime import datetime

from sqlmodel import Field, SQLModel


class TrainingState(SQLModel, table=True):
    __tablename__ = "training_state"

    id: int = Field(default=1, primary_key=True)
    labels_since_last_train: int = Field(default=0)
    last_retrain_at: datetime | None = Field(default=None)