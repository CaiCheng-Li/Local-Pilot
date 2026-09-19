//! Protocol-level tests: health, authentication challenges, discovery
//! metadata, tool listing and SDK client interoperability.

use local_pilot_tests::*;
use serde_json::{Value, json};

#[tokio::test]
async fn health_is_minimal() {
    let h = Harness::new().await;
    let r = h
        .http
        .get(format!("{}/health", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["status"], "ok");
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 2, "health must not disclose anything else: {v}");
}

#[tokio::test]
async fn unauthenticated_requests_get_a_resource_metadata_challenge() {
    let h = Harness::new().await;
    let r = h
        .http
        .post(format!("{}/mcp", h.base))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let www = r
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.starts_with("Bearer resource_metadata=\""), "{www}");
    assert!(
        www.contains("/.well-known/oauth-protected-resource/mcp"),
        "{www}"
    );
    assert!(www.contains("scope=\"workstation:read"), "{www}");

    let r = h
        .rpc(
            "lpm_invalidtokeninvalidtokeninvalid",
            "tools/list",
            json!({}),
        )
        .await;
    assert_eq!(r.status(), 401);
    let www = r
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(www.contains("error=\"invalid_token\""), "{www}");
}

#[tokio::test]
async fn host_header_is_validated() {
    let h = Harness::new().await;
    let r = h
        .http
        .get(format!("{}/health", h.base))
        .header("Host", "evil.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn discovery_metadata() {
    let h = Harness::new().await;
    let prm: Value = h
        .http
        .get(format!(
            "{}/.well-known/oauth-protected-resource/mcp",
            h.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], format!("{}/mcp", h.base));
    assert_eq!(prm["authorization_servers"][0], h.base);
    let asm: Value = h
        .http
        .get(format!("{}/.well-known/oauth-authorization-server", h.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["issuer"], h.base);
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(asm["authorization_response_iss_parameter_supported"], true);
    assert!(
        asm["registration_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/register")
    );
    assert_eq!(asm["client_id_metadata_document_supported"], false);
}

#[tokio::test]
async fn tools_list_has_annotations_and_security_schemes() {
    let h = Harness::new().await;
    let r = h.rpc(&h.token, "tools/list", json!({})).await;
    assert_eq!(r.status(), 200);
    let body = parse_body(&r.text().await.unwrap());
    let tools = body["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "projects_resolve",
        "fs_read_text",
        "fs_write_text",
        "fs_patch",
        "process_run",
        "shell_powershell",
        "shell_cmd",
        "task_output",
        "git_status",
        "git_push",
        "github_pr_create",
        "approval_status",
        "approval_resume",
        "session_current",
        "session_end",
        "admin_request",
        "files_search_text",
        "fs_get_many_metadata",
    ] {
        assert!(names.contains(&expected), "missing {expected}");
    }
    for t in tools {
        let name = t["name"].as_str().unwrap();
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && name.len() <= 64,
            "{name}"
        );
        assert!(
            t["securitySchemes"].is_array(),
            "top-level securitySchemes missing on {name}"
        );
        assert!(t["_meta"]["securitySchemes"].is_array());
        assert!(t["annotations"]["readOnlyHint"].is_boolean(), "{name}");
        assert_eq!(t["inputSchema"]["type"], "object", "{name}");
    }
    let read = tools.iter().find(|t| t["name"] == "fs_read_text").unwrap();
    assert_eq!(read["annotations"]["readOnlyHint"], true);
    let del = tools.iter().find(|t| t["name"] == "fs_delete").unwrap();
    assert_eq!(del["annotations"]["destructiveHint"], true);
}

#[tokio::test]
async fn mcp_method_header_must_match_body() {
    let h = Harness::new().await;
    let r = h
        .http
        .post(format!("{}/mcp", h.base))
        .header("Authorization", format!("Bearer {}", h.token))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Method", "tools/call")
        .body(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn oversized_requests_are_rejected() {
    let mut settings = workstation_core::config::Settings::default();
    settings.network.max_request_body_bytes = 64 * 1024;
    let h = Harness::with(Options {
        settings,
        start_listener: true,
    })
    .await;
    let big = "x".repeat(200 * 1024);
    let r = h
        .rpc(
            &h.token,
            "tools/call",
            json!({ "name": "fs_write_text", "arguments": { "path": "a.txt", "content": big } }),
        )
        .await;
    assert_eq!(r.status(), 413);
}

#[tokio::test]
async fn sdk_client_interoperates() {
    use rmcp::ServiceExt;
    use rmcp::model::CallToolRequestParams;
    use rmcp::transport::StreamableHttpClientTransport;
    use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("Clippy")).unwrap();
    std::fs::write(
        h.projects.join("Clippy").join("Cargo.toml"),
        "[package]\nname='clippy'",
    )
    .unwrap();
    h.core.index.full_scan().unwrap();
    let config = StreamableHttpClientTransportConfig::with_uri(format!("{}/mcp", h.base))
        .auth_header(h.token.clone());
    let transport = StreamableHttpClientTransport::from_config(config);
    let client = ().serve(transport).await.expect("client connects");
    let tools = client.list_all_tools().await.unwrap();
    assert!(tools.len() > 40, "{}", tools.len());
    let mut args = serde_json::Map::new();
    args.insert("name".into(), json!("clippy"));
    let result = client
        .call_tool(CallToolRequestParams::new("projects_resolve").with_arguments(args))
        .await
        .unwrap();
    assert_eq!(result.is_error, Some(false));
    let v = result.structured_content.unwrap();
    assert!(
        v["path"].as_str().unwrap().ends_with(r"Projects\Clippy"),
        "{v}"
    );
    client.cancel().await.ok();
}
