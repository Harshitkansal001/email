import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app, base_url="http://127.0.0.1") as test_client:
        yield test_client
