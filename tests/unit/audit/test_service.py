"""
Unit tests for AuditLogger service.

Validates: Requirements 3.1, 3.3, 3.6
"""

import json
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from registry.audit import AuditLogger, Identity, RegistryApiAccessRecord, Request, Response


def make_test_record(request_id: str = "test-123") -> RegistryApiAccessRecord:
    """Create a test audit record."""
    return RegistryApiAccessRecord(
        timestamp=datetime.now(timezone.utc),
        request_id=request_id,
        identity=Identity(username="testuser", auth_method="oauth2", credential_type="bearer_token"),
        request=Request(method="GET", path="/api/test", client_ip="127.0.0.1"),
        response=Response(status_code=200, duration_ms=50.5),
    )


class TestFileCreation:
    """Tests for file creation on first event."""

    async def test_file_created_on_first_event(self):
        """A new file is created when the first event is logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir, stream_name="test-stream")
            assert not logger.is_open
            
            await logger.log_event(make_test_record())
            
            assert logger.is_open
            assert logger.current_file_path.exists()
            await logger.close()


class TestJSONLFormat:
    """Tests for JSON Lines format output."""

    async def test_output_is_valid_jsonl(self):
        """Each logged event is a valid JSON line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir, stream_name="test-stream")
            
            for i in range(3):
                await logger.log_event(make_test_record(f"request-{i}"))
            
            file_path = logger.current_file_path
            await logger.close()
            
            with open(file_path, "r") as f:
                lines = f.readlines()
            
            assert len(lines) == 3
            for i, line in enumerate(lines):
                parsed = json.loads(line.strip())
                assert parsed["request_id"] == f"request-{i}"


class TestFilenamePattern:
    """Tests for filename pattern matching."""

    async def test_filename_matches_pattern(self):
        """Filename follows pattern {stream}-{ISO8601_timestamp}.jsonl."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir, stream_name="registry-api-access")
            await logger.log_event(make_test_record())
            
            filename = logger.current_file_path.name
            pattern = r"registry-api-access-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.jsonl"
            assert re.match(pattern, filename)
            await logger.close()


class TestRotation:
    """Tests for file rotation."""

    async def test_time_based_rotation_trigger(self):
        """_should_rotate returns True when time threshold exceeded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(log_dir=tmpdir, rotation_hours=1, stream_name="test-stream")
            await logger.log_event(make_test_record())
            
            assert not await logger._should_rotate()
            
            # Simulate time passing
            logger._current_file_start = datetime.now(timezone.utc) - timedelta(hours=2)
            assert await logger._should_rotate()
            
            await logger.close()
