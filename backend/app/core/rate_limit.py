import os

from slowapi import Limiter
from slowapi.util import get_remote_address

# Disable rate limiting in test mode so suite runs aren't throttled.
limiter = Limiter(key_func=get_remote_address, enabled=not os.getenv("TESTING"))
