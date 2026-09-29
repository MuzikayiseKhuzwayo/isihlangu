from isihlangu.recon.mcp_inspector import MCPInspector


def test_mcp_inspector_parse_and_sensitivity() -> None:
    sample_data = {
        "tools": [
            {
                "name": "fetch_web_documentation",
                "description": "Fetches external web documentation from a given URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"],
                },
            },
            {
                "name": "delete_user_record",
                "description": "Deletes a user record.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"user_id": {"type": "string"}},
                    "required": ["user_id"],
                },
            },
        ]
    }

    inspector = MCPInspector()
    tools = inspector.parse_tools_response(sample_data)

    assert len(tools) == 2
    fetch_tool = tools[0]
    delete_tool = tools[1]

    assert fetch_tool.name == "fetch_web_documentation"
    assert fetch_tool.is_sensitive is True  # Contains 'fetch'

    assert delete_tool.name == "delete_user_record"
    assert delete_tool.is_sensitive is True  # Contains 'delete'

    # Audit deficiencies
    deficiencies = inspector.identify_schema_deficiencies(delete_tool)
    assert any("tenant" in d.lower() for d in deficiencies)
    assert any("unbounded string" in d.lower() for d in deficiencies)
