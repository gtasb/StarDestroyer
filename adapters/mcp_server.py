"""MCP adapter. Forwarding only -- 50 lines is the hard ceiling."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from mcp.server.mcpserver import MCPServer

from core.toolset import TOOLS

server = MCPServer("stardestroyer")

for _name, _fn, _doc in TOOLS:
    server.tool(name=_name, description=_doc)(_fn)

if __name__ == "__main__":
    server.run()
