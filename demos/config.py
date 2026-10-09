import os
from pathlib import Path

DEEPSEEK_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
CONNECTOR_URL = os.getenv("CONNECTOR_URL", "http://localhost:9091")
CONNECTOR_DEV_MODE = os.getenv("CONNECTOR_DEV_MODE", "")
CONNECTOR_API_KEY = os.getenv("CONNECTOR_API_KEY", "")
KNOWLEDGE_FILE = Path(__file__).parent / "medical_knowledge.txt"

SYSTEM_KNOWLEDGE = KNOWLEDGE_FILE.read_text()
