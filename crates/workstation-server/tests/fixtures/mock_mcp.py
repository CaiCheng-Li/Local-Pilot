"""Tiny protocol fixture. Never writes diagnostics to stdout."""
import json
import os
import sys
import threading
import time

lock = threading.Lock()
cancelled = set()

def send(value):
    with lock:
        print(json.dumps(value), flush=True)

def handle(message):
    ident = message.get("id")
    method = message.get("method")
    params = message.get("params", {})
    if method == "notifications/cancelled":
        cancelled.add(params.get("requestId"))
        return
    if ident is None:
        return
    if method == "initialize":
        result = {"protocolVersion": params["protocolVersion"], "capabilities": {"tools": {}}, "serverInfo": {"name": "local-pilot-mock", "version": "1"}}
    elif method == "tools/list":
        result = {"tools": [{"name": name, "description": name, "inputSchema": {"type": "object", "additionalProperties": True}} for name in ["echo", "add", "sleep", "fail", "crash", "malformed"]]}
    elif method == "tools/call":
        name = params["name"]
        args = params.get("arguments", {})
        if name == "crash":
            os._exit(7)
        if name == "malformed":
            print("this is not JSON", flush=True)
            return
        if name == "sleep":
            end = time.monotonic() + args.get("seconds", 5)
            while time.monotonic() < end:
                if ident in cancelled:
                    return
                time.sleep(0.01)
        value = args.get("a", 0) + args.get("b", 0) if name == "add" else args
        result = {"content": [{"type": "text", "text": json.dumps(value)}], "isError": name == "fail"}
    elif method == "ping":
        result = {}
    else:
        send({"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "Not found"}})
        return
    send({"jsonrpc": "2.0", "id": ident, "result": result})

for line in sys.stdin:
    threading.Thread(target=handle, args=(json.loads(line),), daemon=True).start()
