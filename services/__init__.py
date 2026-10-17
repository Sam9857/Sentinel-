"""
BitSentinel service layer.

UI  →  routes (HTTP)  →  services  →  external security APIs

Nothing in this package is imported by the front end. API keys are read from
environment variables (optionally loaded from a local .env file) and never
leave the server.
"""
