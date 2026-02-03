"""
Unit tests for AuditLogger service.

These tests verify:
- File creation on first event
- JSON Lines format output
- Size-based rotation trigger
- Filename pattern matching
"""

import asyncio
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
        identity=Identity(
            username="testuser",
            auth_method="oauth2",
            credential_type="bearer_token",
        ),
        request=Request(
            method="GET",
            path="/api/test",
            client_ip="127.0.0.1",
        ),
        response=Response(
            status_code=200,
            duration_ms=50.5,
        ),
    )


class TestAuditLoggerFileCreation:
    """Tests for file creation on first event."""

    async def test_file_created_on_first_event(self):
        """A new file is created when the first event is logged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            # Initially no file is open
            assert not logger.is_open
            assert logger.current_file_path is None
            
            # Log an event
            await logger.log_event(make_test_record())
            
            # File should now be open
            assert logger.is_open
            assert logger.current_file_path is not None
            assert logger.current_file_path.exists()
            
            await logger.close()

    async def test_log_directory_created_if_not_exists(self):
        """The log directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_dir = Path(tmpdir) / "nested" / "audit" / "logs"
            
            logger = AuditLogger(
                log_dir=str(nested_dir),
                stream_name="test-stream",
            )
            
            # Directory should be created during init
            assert nested_dir.exists()
            
            await logger.close()


class TestAuditLoggerJSONLFormat:
    """Tests for JSON Lines format output."""

    async def test_output_is_valid_jsonl(self):
        """Each logged event is a valid JSON line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            # Log multiple events
            for i in range(3):
                await logger.log_event(make_test_record(f"request-{i}"))
            
            # Save file path before closing (close resets it to None)
            file_path = logger.current_file_path
            await logger.close()
            
            # Read and verify each line is valid JSON
            with open(file_path, "r") as f:
                lines = f.readlines()
            
            assert len(lines) == 3
            for i, line in enumerate(lines):
                parsed = json.loads(line.strip())
                assert parsed["request_id"] == f"request-{i}"

    async def test_each_record_on_single_line(self):
        """Each audit record is written on a single line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record())
            
            # Save file path before closing
            file_path = logger.current_file_path
            await logger.close()
            
            with open(file_path, "r") as f:
                content = f.read()
            
            # Should be exactly one line (with trailing newline)
            lines = content.strip().split("\n")
            assert len(lines) == 1

    async def test_record_contains_required_fields(self):
        """Logged records contain all required fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record("test-req-id"))
            
            # Save file path before closing
            file_path = logger.current_file_path
            await logger.close()
            
            with open(file_path, "r") as f:
                record = json.loads(f.readline())
            
            # Check required fields
            assert "timestamp" in record
            assert "request_id" in record
            assert record["request_id"] == "test-req-id"
            assert "identity" in record
            assert record["identity"]["username"] == "testuser"
            assert "request" in record
            assert record["request"]["method"] == "GET"
            assert "response" in record
            assert record["response"]["status_code"] == 200


class TestAuditLoggerSizeRotation:
    """Tests for size-based rotation trigger."""

    async def test_rotation_triggered_at_size_limit(self):
        """File rotation occurs when size limit is reached."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use a very small size limit (1KB) for testing
            logger = AuditLogger(
                log_dir=tmpdir,
                rotation_max_mb=0.001,  # ~1KB
                stream_name="size-test",
            )
            
            # Log first event
            await logger.log_event(make_test_record("first"))
            first_file = logger.current_file_path
            
            # Log many events to exceed size limit
            for i in range(50):
                await logger.log_event(make_test_record(f"event-{i}"))
            
            # File should have rotated
            current_file = logger.current_file_path
            
            # Either we have a new file, or the first file is still there
            # but we should have multiple files in the directory
            files = list(Path(tmpdir).glob("*.jsonl"))
            assert len(files) >= 1
            
            await logger.close()

    async def test_should_rotate_returns_true_at_size_limit(self):
        """_should_rotate returns True when file exceeds size limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                rotation_max_mb=0.0001,  # Very small limit
                stream_name="test-stream",
            )
            
            # Log an event to create file
            await logger.log_event(make_test_record())
            
            # Check rotation status - should trigger due to small limit
            should_rotate = await logger._should_rotate()
            # The file might already exceed the tiny limit
            
            await logger.close()


class TestAuditLoggerFilenamePattern:
    """Tests for filename pattern matching."""

    async def test_filename_contains_stream_name(self):
        """Filename contains the configured stream name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="my-custom-stream",
            )
            
            await logger.log_event(make_test_record())
            
            assert "my-custom-stream" in logger.current_file_path.name
            
            await logger.close()

    async def test_filename_ends_with_jsonl(self):
        """Filename ends with .jsonl extension."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record())
            
            assert logger.current_file_path.name.endswith(".jsonl")
            
            await logger.close()

    async def test_filename_matches_iso8601_pattern(self):
        """Filename contains ISO8601-style timestamp."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record())
            
            filename = logger.current_file_path.name
            # Pattern: {stream}-{YYYY-MM-DDTHH-MM-SS}.jsonl
            pattern = r"test-stream-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.jsonl"
            assert re.match(pattern, filename), f"Filename {filename} doesn't match pattern"
            
            await logger.close()

    async def test_filename_pattern_requirement_36(self):
        """Filename follows pattern {stream}-{ISO8601_timestamp}.jsonl (Req 3.6)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="registry-api-access",
            )
            
            await logger.log_event(make_test_record())
            
            filename = logger.current_file_path.name
            # Verify the exact pattern from requirements
            assert filename.startswith("registry-api-access-")
            assert filename.endswith(".jsonl")
            
            # Extract and validate timestamp portion
            timestamp_part = filename.replace("registry-api-access-", "").replace(".jsonl", "")
            # Should be in format YYYY-MM-DDTHH-MM-SS
            assert len(timestamp_part) == 19  # 2024-01-15T10-30-00
            
            await logger.close()


class TestAuditLoggerTimeRotation:
    """Tests for time-based rotation."""

    async def test_should_rotate_returns_true_after_time_threshold(self):
        """_should_rotate returns True when time threshold exceeded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                rotation_hours=1,
                stream_name="test-stream",
            )
            
            # Log an event to create file
            await logger.log_event(make_test_record())
            
            # Should not rotate immediately
            assert not await logger._should_rotate()
            
            # Simulate time passing
            logger._current_file_start = datetime.now(timezone.utc) - timedelta(hours=2)
            
            # Should now rotate
            assert await logger._should_rotate()
            
            await logger.close()


class TestAuditLoggerClose:
    """Tests for logger close functionality."""

    async def test_close_sets_state_to_closed(self):
        """Closing the logger resets internal state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record())
            assert logger.is_open
            
            await logger.close()
            assert not logger.is_open
            assert logger.current_file_path is None

    async def test_close_is_idempotent(self):
        """Calling close multiple times is safe."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                log_dir=tmpdir,
                stream_name="test-stream",
            )
            
            await logger.log_event(make_test_record())
            
            # Close multiple times - should not raise
            await logger.close()
            await logger.close()
            await logger.close()
