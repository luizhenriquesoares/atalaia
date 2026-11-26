"""ASGI entry point: uvicorn atalaia.main:app"""
from .api.app import create_app

app = create_app()
