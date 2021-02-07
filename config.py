import os

"""
Config files
"""
URL = "0.0.0.0"
PORT = 5000
MAX_HEART_COUNT = 4
# Max number of requests a user can make in a 24 hour interval
MAX_SEARCH_COUNT = 50
# Max number of results to return to the user while searching
MAX_SEARCH_LIMIT = 6
# Time in minutes for the window of time for rate limit
WINDOW_SIZE_TIME = 60 * 3  # Waiting for 3 hours
# Frontend URL to send the verify hash link
FRONTEND_URL = "https://kgpyaar.fun"
# MONGODB_URL
MONGODB_URL = os.getenv("MONGODB_URL")
# DATA_CSV
DATA_CSV = os.getenv("KGPYAAR_CSV")
# Sendgrid Key
SENDGRID_KEY = "i-smart-u-smart"
# KGPYaar mail
KGPYAAR_EMAIL = "no-reply@kgpyaar.fun"
