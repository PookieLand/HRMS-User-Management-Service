import logging
import sys


def setup_logger(name: str) -> logging.Logger:
    """
    Configure and return a logger with consistent formatting.

    Args:
        name: The name of the logger (typically __name__ from calling module)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    # Add handler only if not already present to avoid duplicates
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("      %(levelname)-5s  %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False  # Don't propagate to root logger to avoid duplicates

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get or create a logger with the standard configuration.

    Args:
        name: The name of the logger (typically __name__ from calling module)

    Returns:
        Configured logger instance
    """
    return setup_logger(name)
