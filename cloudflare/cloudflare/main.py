from workers import asgi
from src.api import app
Default = asgi.entrypoint(app)
