from app import create_app

# Expose a WSGI callable for Gunicorn without --factory
app = create_app()

