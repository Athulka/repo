# app.py

from service import get_random_quote
from config import SHOW_AUTHOR
from logger import setup_logger

"""
This is the main application file for the "Quote of the Day" project.
It retrieves and displays a random quote.
"""

# Initialize the logger
main_logger = setup_logger()

def main():
    """
    The main function to run the application.
    """
    main_logger.info("Application started.")
    print("--- Your Quote of the Day ---")
    
    quote = get_random_quote()
    
    if quote:
        print(f"\n\"{quote['text']}\"")
        if SHOW_AUTHOR and 'author' in quote:
            print(f"- {quote['author']}")
    else:
        print("\nCould not retrieve a quote at this time.")
        main_logger.error("Failed to display a quote.")
    
    print("\n--------------------------")
    main_logger.info("Application finished.")

if __name__ == "__main__":
    main()
