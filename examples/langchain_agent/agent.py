import os
import json
from typing import Any, Dict, Optional

import httpx
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from langchain.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate


load_dotenv()


# ---- Config ---------------------------------------------------------------

BASE_URL = os.environ.get("VAULT_MCP_BASE_URL", "http://127.0.0.1:8089")
API_KEY = os.environ.get("VAULT_MCP_API_KEY")
BEARER_TOKEN = os.environ.get("VAULT_MCP_BEARER_TOKEN")


def _auth_headers() -> Dict[str, str]:
    headers = {}
    if BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {BEARER_TOKEN}"
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers


client = httpx.Client(base_url=BASE_URL, headers=_auth_headers(), timeout=10.0)


# ---- Tool Schemas ---------------------------------------------------------


class WriteArgs(BaseModel):
    path: str = Field(..., description="Relative secret path, e.g., 'configs/db'")
    data: Dict[str, Any] = Field(..., description="Secret key-value data to store")


class ReadArgs(BaseModel):
    path: str
    version: Optional[int] = Field(None, description="Optional version to read")


class DeleteArgs(BaseModel):
    path: str


class ListArgs(BaseModel):
    prefix: str = Field("", description="Prefix to list under")


class UndestroyArgs(BaseModel):
    path: str
    versions: list[int]


class EncryptArgs(BaseModel):
    key: str
    plaintext_b64: str = Field(..., description="Base64-encoded plaintext")


class DecryptArgs(BaseModel):
    key: str
    ciphertext: str


# ---- Tool Implementations -------------------------------------------------


def _rpc(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    r = client.post(f"/mcp/rpc", json=body)
    r.raise_for_status()
    js = r.json()
    if "error" in js:
        raise RuntimeError(f"RPC error: {js['error']}")
    return (js.get("result") or {}).get("content") or {}


def write_secret(path: str, data: Dict[str, Any]) -> str:
    res = _rpc("kv.write", {"path": path, "data": data})
    ok = res.get("ok")
    return f"Wrote secret at '{path}', ok={ok}"


def read_secret(path: str, version: Optional[int] = None) -> str:
    res = _rpc("kv.read", {"path": path, "version": version})
    keys = list((res.get("data") or {}).keys())
    return f"Read secret '{path}', keys={keys}, version={res.get('version')}"


def delete_secret(path: str) -> str:
    _ = _rpc("kv.delete", {"path": path})
    return f"Deleted latest version for '{path}'"


def list_secrets(prefix: str = "") -> str:
    res = _rpc("kv.list", {"prefix": prefix})
    return f"Keys under '{prefix}': {res.get('keys')}"


def undelete_versions(path: str, versions: list[int]) -> str:
    _ = _rpc("kv.undelete", {"path": path, "versions": versions})
    return f"Undeleted versions {versions} for '{path}'"


def destroy_versions(path: str, versions: list[int]) -> str:
    _ = _rpc("kv.destroy", {"path": path, "versions": versions})
    return f"Destroyed versions {versions} for '{path}'"


def transit_encrypt(key: str, plaintext_b64: str) -> str:
    res = _rpc("transit.encrypt", {"key": key, "plaintext": plaintext_b64})
    return res.get("ciphertext", "")


def transit_decrypt(key: str, ciphertext: str) -> str:
    res = _rpc("transit.decrypt", {"key": key, "ciphertext": ciphertext})
    return res.get("plaintext", "")


# ---- Build Tools -----------------------------------------------------------

tools = [
    StructuredTool.from_function(
        name="secret_write",
        description="Write a secret JSON object at the given relative path within the agent's namespace.",
        func=write_secret,
        args_schema=WriteArgs,
    ),
    StructuredTool.from_function(
        name="secret_read",
        description="Read a secret at the given relative path. Returns metadata and key names only.",
        func=read_secret,
        args_schema=ReadArgs,
    ),
    StructuredTool.from_function(
        name="secret_delete",
        description="Delete the latest version of a secret at the given path.",
        func=delete_secret,
        args_schema=DeleteArgs,
    ),
    StructuredTool.from_function(
        name="secret_list",
        description="List keys under the given prefix.",
        func=list_secrets,
        args_schema=ListArgs,
    ),
    StructuredTool.from_function(
        name="secret_undelete",
        description="Undelete specific versions for a path.",
        func=undelete_versions,
        args_schema=UndestroyArgs,
    ),
    StructuredTool.from_function(
        name="secret_destroy",
        description="Permanently destroy specific versions for a path.",
        func=destroy_versions,
        args_schema=UndestroyArgs,
    ),
    StructuredTool.from_function(
        name="transit_encrypt",
        description="Encrypt base64 plaintext using Vault transit key.",
        func=transit_encrypt,
        args_schema=EncryptArgs,
    ),
    StructuredTool.from_function(
        name="transit_decrypt",
        description="Decrypt a Vault transit ciphertext.",
        func=transit_decrypt,
        args_schema=DecryptArgs,
    ),
]


def build_agent():
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    system = (
        "You are an assistant that manages secrets for your own namespace "
        "using provided tools. Only operate within the given relative paths. "
        "Do not reveal raw secret values unless explicitly requested by the user."
    )
    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", "{input}"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="Create a secret at configs/demo with {\"foo\":\"bar\"} then read it back.")
    args = ap.parse_args()

    ex = build_agent()
    res = ex.invoke({"input": args.input})
    print("Result:\n", res)
