from celery import Celery
import logging
import sys

# Keep our task logger output visible in the worker terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

celery = Celery(
    "easm",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
    include=["tasks"]
)

celery.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Kolkata",
    enable_utc=True,
    worker_redirect_stdouts=False,
    worker_hijack_root_logger=False,
    # ── Windows fix: prefork fails on Windows, solo pool works correctly ──
    worker_pool="solo",
    # ── Suppress the broker_connection_retry deprecation warning ──
    broker_connection_retry_on_startup=True,
)
