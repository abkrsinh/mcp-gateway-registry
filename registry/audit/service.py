"""
AuditLogger service for async writing and file rotation.

This module provides the core audit logging service that writes
audit events to local JSONL buffer files with time and size-based
rotation policies. Optionally writes to MongoDB for warm storage.
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

import aiofiles
import aiofiles.os

from .models import RegistryApiAccessRecord

if TYPE_CHECKING:
    from ..repositories.audit_repository import AuditRepositoryBase

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Async audit logger with file rotation support.
    
    Writes audit events to local JSONL buffer files with configurable
    time-based and size-based rotation policies. Supports automatic
    cleanup of old files based on retention settings.
    
    Attributes:
        log_dir: Directory for audit log files
        rotation_hours: Hours between time-based rotations
        rotation_max_bytes: Maximum file size before rotation
        local_retention_hours: Hours to retain local files
    """
    
    def __init__(
        self,
        log_dir: str = "logs/audit",
        rotation_hours: int = 1,
        rotation_max_mb: int = 100,
        local_retention_hours: int = 24,
        stream_name: str = "registry-api-access",
        mongodb_enabled: bool = False,
        audit_repository: Optional["AuditRepositoryBase"] = None,
    ):
        """
        Initialize the AuditLogger.
        
        Args:
            log_dir: Directory path for audit log files
            rotation_hours: Hours between time-based file rotations
            rotation_max_mb: Maximum file size in MB before rotation
            local_retention_hours: Hours to retain local files before cleanup
            stream_name: Name of the audit stream for filename prefix
            mongodb_enabled: Whether to write audit events to MongoDB
            audit_repository: Repository for MongoDB writes (required if mongodb_enabled)
        """
        self.log_dir = Path(log_dir)
        self.rotation_hours = rotation_hours
        self.rotation_max_bytes = rotation_max_mb * 1024 * 1024
        self.local_retention_hours = local_retention_hours
        self.stream_name = stream_name
        self.mongodb_enabled = mongodb_enabled
        self._audit_repository = audit_repository
        
        # Current file state
        self._current_file: Optional[aiofiles.threadpool.binary.AsyncBufferedIOBase] = None
        self._current_file_path: Optional[Path] = None
        self._current_file_start: Optional[datetime] = None
        
        # Lock for thread-safe file operations
        self._lock = asyncio.Lock()
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    async def log_event(
        self,
        record: Union[RegistryApiAccessRecord, "MCPServerAccessRecord"],
    ) -> None:
        """
        Write an audit record to the current buffer file and optionally MongoDB.
        
        This method is thread-safe and handles file rotation automatically.
        Records are written as JSON Lines (one JSON object per line).
        If MongoDB is enabled, records are also written to MongoDB for warm storage.
        
        Args:
            record: The audit record to log (RegistryApiAccessRecord or MCPServerAccessRecord)
        """
        # Write to local file
        async with self._lock:
            try:
                await self._ensure_file_open()
                
                if await self._should_rotate():
                    await self._rotate_file()
                
                # Serialize record to JSON and write with newline
                line = record.model_dump_json() + "\n"
                await self._current_file.write(line.encode("utf-8"))
                await self._current_file.flush()
                
            except Exception as e:
                logger.error(f"Failed to write audit event to file: {e}")
                # Don't raise - audit logging should not break request processing
        
        # Write to MongoDB (if enabled)
        if self.mongodb_enabled and self._audit_repository:
            try:
                await self._audit_repository.insert(record)
            except Exception as e:
                logger.error(f"Failed to write audit event to MongoDB: {e}")
                # Fall back to local file only - don't raise
    
    async def _ensure_file_open(self) -> None:
        """
        Ensure a file is open for writing.
        
        Opens a new file if no file is currently open.
        """
        if self._current_file is None:
            await self._open_new_file()
    
    async def _open_new_file(self) -> None:
        """
        Open a new audit log file with timestamped filename.
        
        Filename format: {stream_name}-{ISO8601_timestamp}.jsonl
        Example: registry-api-access-2024-01-15T10-30-00.jsonl
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"{self.stream_name}-{timestamp}.jsonl"
        self._current_file_path = self.log_dir / filename
        self._current_file = await aiofiles.open(self._current_file_path, mode="ab")
        self._current_file_start = datetime.now(timezone.utc)
        logger.debug(f"Opened new audit log file: {self._current_file_path}")
    
    async def _should_rotate(self) -> bool:
        """
        Check if the current file should be rotated.
        
        Rotation occurs when:
        - Time since file creation exceeds rotation_hours
        - File size exceeds rotation_max_bytes
        
        Returns:
            True if rotation is needed, False otherwise
        """
        if self._current_file_path is None or self._current_file_start is None:
            return False
        
        # Check time-based rotation
        elapsed = datetime.now(timezone.utc) - self._current_file_start
        if elapsed >= timedelta(hours=self.rotation_hours):
            logger.debug(f"Time-based rotation triggered after {elapsed}")
            return True
        
        # Check size-based rotation
        try:
            file_size = self._current_file_path.stat().st_size
            if file_size >= self.rotation_max_bytes:
                logger.debug(f"Size-based rotation triggered at {file_size} bytes")
                return True
        except OSError as e:
            logger.warning(f"Could not check file size: {e}")
        
        return False
    
    async def _rotate_file(self) -> None:
        """
        Rotate the current log file.
        
        Closes the current file and opens a new one. Also triggers
        cleanup of old files that exceed the retention period.
        """
        if self._current_file:
            try:
                await self._current_file.close()
                logger.info(f"Rotated audit log file: {self._current_file_path}")
            except Exception as e:
                logger.error(f"Error closing audit log file: {e}")
        
        self._current_file = None
        self._current_file_path = None
        self._current_file_start = None
        
        # Open new file
        await self._open_new_file()
        
        # Trigger cleanup of old files (fire-and-forget)
        asyncio.create_task(self._cleanup_old_files())
    
    async def _cleanup_old_files(self) -> None:
        """
        Remove audit log files older than the retention period.
        
        Files are deleted if their modification time is older than
        local_retention_hours from the current time.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.local_retention_hours)
        cutoff_timestamp = cutoff.timestamp()
        
        try:
            for file_path in self.log_dir.glob("*.jsonl"):
                try:
                    # Skip the current file
                    if self._current_file_path and file_path == self._current_file_path:
                        continue
                    
                    file_mtime = file_path.stat().st_mtime
                    if file_mtime < cutoff_timestamp:
                        file_path.unlink()
                        logger.info(f"Cleaned up old audit log file: {file_path}")
                        
                except OSError as e:
                    logger.warning(f"Could not clean up file {file_path}: {e}")
                    
        except Exception as e:
            logger.error(f"Error during audit log cleanup: {e}")
    
    async def close(self) -> None:
        """
        Close the current log file.
        
        Should be called during application shutdown to ensure
        all data is flushed and the file is properly closed.
        """
        async with self._lock:
            if self._current_file:
                try:
                    await self._current_file.close()
                    logger.info(f"Closed audit log file: {self._current_file_path}")
                except Exception as e:
                    logger.error(f"Error closing audit log file: {e}")
                finally:
                    self._current_file = None
                    self._current_file_path = None
                    self._current_file_start = None
    
    @property
    def current_file_path(self) -> Optional[Path]:
        """Get the path of the current log file."""
        return self._current_file_path
    
    @property
    def is_open(self) -> bool:
        """Check if a log file is currently open."""
        return self._current_file is not None
