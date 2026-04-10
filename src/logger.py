"""
Centralized management for logs. Logs are stored in a folder LOG_DIR

Terminal log possible also but commented below to avoid polluting terminal.

UTF-8 encoding possible.
"""

from import_data import *

# checks whether the log folder does exist
os.makedirs(LOG_DIR, exist_ok=True)

# Build log filename.  Use the date
log_filename = os.path.join(LOG_DIR, f"ATLAS_{datetime.now().strftime('%Y-%m-%d')}.log")

# Creating global logger
logger = logging.getLogger("ATLAS")
logger.setLevel(logging.DEBUG)  # Capture everything wiht level DEBUG

# Standard formatter with timestamp, level and message
formatter = logging.Formatter(
    '%(asctime)s - %(filename)s - %(lineno)d - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
)

# File handler
file_handler = logging.FileHandler(log_filename, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

def log_info(msg: str) -> None:
    logger.info(msg)

def log_warning(msg: str) -> None:
    logger.warning(msg)

def log_error(msg: str) -> None:
    logger.error(msg)

def log_exception(msg: str) -> None:
    """
    Logs an error message with exception traceback

    To be used in an "except" block.
    """
    logger.exception(msg)
