# service.py

import random
from quotes import QUOTES
from logger import setup_logger

"""
This module provides the service for getting a random quote.
"""

# Initialize the logger
app_logger = setup_logger()

def get_random_quote():
    """
    Selects and returns a random quote from the list of quotes.

    Returns:
        dict: A dictionary containing the 'text' and 'author' of a quote,
              or None if the quotes list is empty.
    """
    app_logger.info("Attempting to retrieve a random quote.")
    if not QUOTES:
        app_logger.warning("The quotes list is empty.")
        return None
    
    try:
        quote = random.choice(QUOTES)
        app_logger.info(f"Successfully retrieved quote by {quote.get('author')}.")
        return quote
    except IndexError:
        app_logger.error("An IndexError occurred while trying to select a random quote.")
        return None
    except Exception as e:
        app_logger.error(f"An unexpected error occurred: {e}")
        return None
