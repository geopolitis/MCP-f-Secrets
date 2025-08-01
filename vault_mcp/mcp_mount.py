def mount_fastapi_mcp(app):
    try:
        from fastapi_mcp import FastApiMCP
        mcp = FastApiMCP(app)
        try:
            mcp.mount_http(app, "/mcp")
        except TypeError:
            mcp.mount_http("/mcp")
    except Exception as e:
        print(f"[WARN] MCP not mounted: {e}")