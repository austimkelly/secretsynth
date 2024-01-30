import logging
import os

def setup_error_logger(error_logfile):
    # Create a logger
    logger = logging.getLogger('gitleaks-utils-logger')

    # Set the level to ERROR. This means the logger will handle ERROR and CRITICAL messages
    logger.setLevel(logging.ERROR)

    # Check if the file exists and create it if it doesn't
    if not os.path.exists(error_logfile):
        open(error_logfile, 'a').close()

    # Create a file handler
    handler = logging.FileHandler(error_logfile)

    # Create a formatter and add it to the handler
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    return logger