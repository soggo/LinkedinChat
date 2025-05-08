# wsgi.py
# Make sure this file is in the same directory as main.py

# Import the app directly from main module
from main import app

# This line is important - it explicitly makes the 'app' variable available for Gunicorn
if __name__ == "__main__":
    # This block is not used by Gunicorn but can be useful for local testing
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)