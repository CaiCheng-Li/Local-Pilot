use super::*;

fn fixture(id: &str) -> ServerConfig {
    ServerConfig {
        id: id.into(),
        name: id.into(),
        command: "python.exe".into(),
        cwd: env!("CARGO_MANIFEST_DIR").into(),
        args: vec![format!(
            "{}/tests/fixtures/mock_mcp.py",
            env!("CARGO_MANIFEST_DIR")
        )],
        tool_timeout_seconds: 1,
        ..Default::default()
    }
}

#[test]
fn config_validation_and_loopback_only() {
    for url in [
        "http://127.0.0.1:123/mcp",
        "http://localhost:123/mcp",
        "http://[::1]:123/mcp",
    ] {
        assert!(local_url(url).is_ok(), "{url}");
    }
    for url in [
        "https://example.com/mcp",
        "http://127.0.0.1.evil.test/mcp",
        "http://user:pass@localhost/mcp",
        "http://localhost/mcp?token=secret",
        "file:///tmp/mcp",
        "http://0.0.0.0/mcp",
    ] {
        assert!(local_url(url).is_err(), "{url}");
    }
    let mut c = fixture("valid-id");
    assert!(c.validate().is_ok());
    c.id = "../bad".into();
    assert!(c.validate().is_err());
    assert_eq!(
        policy::effective_risk("safe_read_file", &json!({}), RiskClass::Unknown),
        RiskClass::Unknown
    );
    assert_eq!(
        policy::effective_risk("execute_python", &json!({}), RiskClass::ReadOnly),
        RiskClass::ArbitraryCode
    );
    assert_eq!(
        policy::effective_risk("anything", &json!({"code":"pass"}), RiskClass::ReadOnly),
        RiskClass::ArbitraryCode
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stdio_lifecycle_concurrency_timeout_crash_and_registry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcp.db");
    let g = Gateway::open(&path, Redactor::new()).unwrap();
    g.resume();
    let mut config = fixture("one");
    config.env.insert(
        "MCP_TEST_SECRET".into(),
        "gateway-secret-value-123456".into(),
    );
    g.save(config.clone(), false).await.unwrap();
    assert!(g.save(config, false).await.is_err());
    g.save(fixture("two"), false).await.unwrap();
    g.start("one").await.unwrap();
    g.start("two").await.unwrap();
    assert_eq!(g.get("one").unwrap()["runtime"]["status"], "connected");
    assert_eq!(g.tools("one").unwrap().as_array().unwrap().len(), 6);
    assert!(!g.get("one").unwrap().to_string().contains("gateway-secret"));
    let desc = g.descriptor("one", Some("add")).unwrap();
    let calls = (0..8).map(|n| {
        g.call(
            "one",
            "add",
            json!({"a":n,"b":2}),
            &desc,
            CancellationToken::new(),
        )
    });
    let result = futures::future::join_all(calls).await;
    for (n, r) in result.into_iter().enumerate() {
        assert_eq!(r.unwrap()["content"][0]["text"], (n + 2).to_string());
    }
    let desc = g.descriptor("one", Some("sleep")).unwrap();
    assert_eq!(
        g.call(
            "one",
            "sleep",
            json!({"seconds":5}),
            &desc,
            CancellationToken::new()
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::McpToolTimeout
    );
    let token = CancellationToken::new();
    token.cancel();
    assert!(
        g.call("one", "sleep", json!({"seconds":5}), &desc, token)
            .await
            .is_err()
    );
    let desc = g.descriptor("one", Some("crash")).unwrap();
    assert!(
        g.call("one", "crash", json!({}), &desc, CancellationToken::new())
            .await
            .is_err()
    );
    g.restart("one").await.unwrap();
    let desc = g.descriptor("one", Some("sleep")).unwrap();
    let pending = g.call(
        "one",
        "sleep",
        json!({"seconds":5}),
        &desc,
        CancellationToken::new(),
    );
    let stop = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        g.block();
    };
    let (result, _) = tokio::join!(pending, stop);
    assert!(result.is_err());
    assert!(g.start("two").await.is_err());
    let saved = Gateway::open(&path, Redactor::new()).unwrap();
    assert_eq!(
        saved.config("one").unwrap().env["MCP_TEST_SECRET"],
        "gateway-secret-value-123456"
    );
    let raw = std::fs::read(&path).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("gateway-secret-value-123456"));
    g.remove("one").await.unwrap();
    assert!(g.get("one").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_retry_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mcp_retry.db");
    let g = Gateway::open(&path, Redactor::new()).unwrap();
    g.resume();
    let mut config = fixture("retry");
    config.reconnect_attempts = 1;
    g.save(config.clone(), false).await.unwrap();

    g.start("retry").await.unwrap();
    assert_eq!(g.get("retry").unwrap()["runtime"]["status"], "connected");
    assert_eq!(g.get("retry").unwrap()["runtime"]["restartCount"], 0);

    let desc = g.descriptor("retry", Some("crash")).unwrap();
    let _ = g.call("retry", "crash", json!({}), &desc, CancellationToken::new()).await;

    // First reconnect attempt will increase restart_count to 1
    g.maintain().await;
    
    // We must wait for the backoff, since restart_count was 0, backoff is 1 second
    tokio::time::sleep(Duration::from_millis(1100)).await;
    g.maintain().await; // This will trigger the start()
    
    assert_eq!(g.get("retry").unwrap()["runtime"]["status"], "connected");
    assert_eq!(g.get("retry").unwrap()["runtime"]["restartCount"], 0);

    let _ = g.call("retry", "crash", json!({}), &desc, CancellationToken::new()).await;

    // Second reconnect attempt should still work because restart_count was reset!
    g.maintain().await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    g.maintain().await;

    assert_eq!(g.get("retry").unwrap()["runtime"]["status"], "connected");
}
