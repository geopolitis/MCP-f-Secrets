import os, sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from vault_mcp.app import create_app
app = create_app()

if __name__ == "__main__":
    # Optional: run directly with `python main.py` to avoid uvicorn target syntax.
    import os
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8089"))
    reload = os.environ.get("RELOAD", "true").lower() in ("1", "true", "yes")
    log_level_env = os.environ.get("LOG_LEVEL", "info")
    try:
        # Allow numeric `logging` levels while normalizing strings for uvicorn
        log_level = int(log_level_env)
    except ValueError:
        log_level = log_level_env.lower()

    uvicorn.run("main:app", host=host, port=port, reload=reload, log_level=log_level)
