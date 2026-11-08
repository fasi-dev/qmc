"""Application entry point for the (fictional) payment API."""
from src.api import routes

ROUTES = {"session": routes.issue_session, "settle": routes.store_settlement}
