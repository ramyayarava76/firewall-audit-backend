"""
Centralized logging configuration for the Firewall Audit Backend.

Provides logging setup for all modules with support for:
- Console output
- File output
- Structured logging
- Different log levels
- Request/response tracking
"""

import logging
import logging.handlers
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

# Log directory
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Log file paths
LOG_FILE = LOG_DIR / f"firewall_audit_{datetime.now().strftime('%Y%m%d')}.log"
ERROR_LOG_FILE = LOG_DIR / f"firewall_audit_errors_{datetime.now().strftime('%Y%m%d')}.log"

# Log format
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DETAILED_LOG_FORMAT = (
    "%(asctime)s - %(name)s - %(levelname)s - "
    "[%(filename)s:%(lineno)d] - %(funcName)s() - %(message)s"
)


def setup_logging(
    level: str = "INFO",
    console_output: bool = True,
    file_output: bool = True,
    detailed: bool = False,
) -> None:
    """
    Configure logging for the entire application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console_output: Whether to output logs to console
        file_output: Whether to output logs to files
        detailed: Whether to use detailed log format with function names and line numbers
    """
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Choose format
    log_format = DETAILED_LOG_FORMAT if detailed else LOG_FORMAT
    formatter = logging.Formatter(log_format)

    # Console handler
    if console_output:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    # File handler - General logs
    if file_output:
        file_handler = logging.handlers.RotatingFileHandler(
            LOG_FILE,
            maxBytes=10485760,  # 10MB
            backupCount=5,
        )
        file_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

        # File handler - Error logs only
        error_handler = logging.handlers.RotatingFileHandler(
            ERROR_LOG_FILE,
            maxBytes=10485760,  # 10MB
            backupCount=5,
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        root_logger.addHandler(error_handler)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a module.

    Args:
        name: Module name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class RequestLogger:
    """Helper class for logging API requests and responses."""

    @staticmethod
    def log_request(
        method: str,
        path: str,
        status_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        details: Optional[dict] = None,
    ) -> None:
        """
        Log an API request/response.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path
            status_code: HTTP status code
            duration_ms: Request duration in milliseconds
            details: Additional details dictionary
        """
        logger = get_logger("api.request")
        message = f"{method} {path}"
        if status_code:
            message += f" -> {status_code}"
        if duration_ms is not None:
            message += f" ({duration_ms:.2f}ms)"
        if details:
            message += f" | {details}"
        logger.info(message)

    @staticmethod
    def log_error(
        method: str,
        path: str,
        error: str,
        status_code: int = 500,
    ) -> None:
        """
        Log an API error.

        Args:
            method: HTTP method
            path: URL path
            error: Error message
            status_code: HTTP status code
        """
        logger = get_logger("api.error")
        logger.error(f"{method} {path} -> {status_code} | {error}")


class TaskLogger:
    """Helper class for logging background tasks and operations."""

    @staticmethod
    def log_task_start(task_name: str, details: Optional[dict] = None) -> None:
        """Log the start of a background task."""
        logger = get_logger("tasks")
        message = f"Starting task: {task_name}"
        if details:
            message += f" | {details}"
        logger.info(message)

    @staticmethod
    def log_task_complete(task_name: str, details: Optional[dict] = None) -> None:
        """Log successful completion of a background task."""
        logger = get_logger("tasks")
        message = f"Completed task: {task_name}"
        if details:
            message += f" | {details}"
        logger.info(message)

    @staticmethod
    def log_task_error(task_name: str, error: str) -> None:
        """Log an error in a background task."""
        logger = get_logger("tasks")
        logger.error(f"Task error in {task_name}: {error}")


class AnalysisLogger:
    """Helper class for logging analysis operations."""

    @staticmethod
    def log_analysis_start(analysis_type: str, rule_count: int) -> None:
        """Log the start of an analysis."""
        logger = get_logger("analysis")
        logger.info(f"Starting {analysis_type} analysis on {rule_count} rules")

    @staticmethod
    def log_analysis_complete(
        analysis_type: str,
        rule_count: int,
        findings: Optional[dict] = None,
    ) -> None:
        """Log successful completion of an analysis."""
        logger = get_logger("analysis")
        message = f"Completed {analysis_type} analysis on {rule_count} rules"
        if findings:
            message += f" | {findings}"
        logger.info(message)

    @staticmethod
    def log_analysis_error(analysis_type: str, error: str) -> None:
        """Log an error during analysis."""
        logger = get_logger("analysis")
        logger.error(f"Error in {analysis_type} analysis: {error}")


# Initialize logging when module is imported
if os.getenv("DISABLE_LOGGING") != "true":
    setup_logging(
        level=os.getenv("LOG_LEVEL", "INFO"),
        console_output=True,
        file_output=True,
        detailed=os.getenv("DETAILED_LOGS", "false").lower() == "true",
    )
