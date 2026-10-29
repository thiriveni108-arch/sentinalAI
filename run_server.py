"""Entry point for running SentinelAI FastAPI backend with Railway PORT support."""

import os
import uvicorn


def get_port() -> int:
    return int(os.environ.get("PORT", "8000"))


def get_host() -> str:
    return os.environ.get("HOST", "0.0.0.0")


def main() -> None:
    port = get_port()
    host = get_host()
    uvicorn.run("sentinel_ai.api.app:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
