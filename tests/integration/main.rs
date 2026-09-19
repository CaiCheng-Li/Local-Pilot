//! End-to-end acceptance scenarios (plan section 61) driven through the
//! MCP HTTP endpoint with manual bearer tokens. Filesystem-policy cases use
//! structured tools; raw-shell cases verify the documented best-effort checks.

use std::time::Duration;

use local_pilot_tests::*;
use serde_json::{Value, json};
use workstation_server::approvals::LocalDecision;

// ------------------------------------------------------------ A, B, C, D, E

#[tokio::test]
async fn a_resolve_project() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("Clippy").join("src")).unwrap();
    std::fs::write(h.projects.join("Clippy").join("package.json"), "{}").unwrap();
    h.core.index.full_scan().unwrap();
    let v = h.ok("projects_resolve", json!({ "name": "Clippy" })).await;
    assert_eq!(v["name"], "Clippy");
    assert_eq!(v["path"], h.path("Clippy"));
    assert_eq!(v["confidence"], 1.0);
    let list = h.ok("projects_list", json!({})).await;
    assert_eq!(list["count"], 1);
    assert_eq!(
        h.err("projects_resolve", json!({ "name": "Nonexistent-Thing" }))
            .await,
        "PROJECT_NOT_FOUND"
    );
}

#[tokio::test]
async fn b_c_create_edit_run_delete_inside_projects() {
    let h = Harness::new().await;
    // B: create a project without approval.
    let v = h.ok("fs_mkdir", json!({ "path": "TestProject" })).await;
    assert_eq!(v["created"], true);
    // C: create, edit, run, delete ordinary files.
    h.ok(
        "fs_write_text",
        json!({ "path": "TestProject/hello.txt", "content": "hello world\n" }),
    )
    .await;
    let r = h
        .ok("fs_read_text", json!({ "path": "TestProject/hello.txt" }))
        .await;
    assert_eq!(r["content"], "hello world\n");
    h.ok("fs_patch", json!({ "path": "TestProject/hello.txt", "edits": [{ "old_text": "world", "new_text": "pilot" }] })).await;
    let r = h
        .ok(
            "fs_read_text",
            json!({ "path": h.path("TestProject/hello.txt") }),
        )
        .await;
    assert_eq!(r["content"], "hello pilot\n");
    let out = h
        .ok(
            "shell_cmd",
            json!({ "command": "type hello.txt", "cwd": h.path("TestProject") }),
        )
        .await;
    assert_eq!(out["status"], "completed", "{out}");
    assert!(out["output"].as_str().unwrap().contains("hello pilot"));
    h.ok(
        "fs_copy",
        json!({ "source": "TestProject/hello.txt", "destination": "TestProject/copy.txt" }),
    )
    .await;
    h.ok("fs_move", json!({ "source": "TestProject/copy.txt", "destination": "TestProject/sub/moved.txt", "create_parents": true })).await;
    let list = h.ok("fs_list", json!({ "path": "TestProject" })).await;
    let names: Vec<&str> = list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"sub") && names.contains(&"hello.txt"),
        "{list}"
    );
    h.ok("fs_delete", json!({ "path": "TestProject/hello.txt" }))
        .await;
    assert!(!h.projects.join("TestProject").join("hello.txt").exists());
    assert_eq!(
        h.err("fs_delete", json!({ "path": "TestProject" })).await,
        "COMMAND_FAILED",
    );
    h.ok(
        "fs_delete",
        json!({ "path": "TestProject", "recursive": true }),
    )
    .await;
    assert!(!h.projects.join("TestProject").exists());
}

#[tokio::test]
async fn d_external_read_is_allowed() {
    let h = Harness::new().await;
    let f = h.outside.join("notes.txt");
    std::fs::write(&f, "outside note").unwrap();
    let r = h
        .ok("fs_read_text", json!({ "path": f.display().to_string() }))
        .await;
    assert_eq!(r["content"], "outside note");
}

#[tokio::test]
async fn e_protected_reads_are_denied() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("App")).unwrap();
    std::fs::write(
        h.projects.join("App").join(".env"),
        "API_TOKEN=supersecretvalue123",
    )
    .unwrap();
    std::fs::create_dir_all(h.outside.join(".ssh")).unwrap();
    std::fs::write(
        h.outside.join(".ssh").join("id_rsa"),
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    for p in [
        h.path("App/.env"),
        h.outside.join(".ssh").join("id_rsa").display().to_string(),
        "~/.ssh/id_rsa".to_string(),
    ] {
        let (err, v) = h.call("fs_read_text", json!({ "path": p })).await;
        assert!(err, "{p}: {v}");
        assert_eq!(v["error"]["code"], "PROTECTED_RESOURCE", "{p}: {v}");
        assert!(!v.to_string().contains("supersecret") && !v.to_string().contains("AAAA"));
    }
    // Metadata is allowed; content is not.
    let st = h.ok("fs_stat", json!({ "path": h.path("App/.env") })).await;
    assert_eq!(st["protected"], true);
    // Search never reads protected files.
    let s = h
        .ok(
            "files_search_text",
            json!({ "query": "supersecret", "scope": h.path("App") }),
        )
        .await;
    assert_eq!(s["hits"].as_array().unwrap().len(), 0);
    assert_eq!(s["protected_skipped"], 1);
    // Copying a protected file into the workspace is not a bypass.
    assert_eq!(
        h.err(
            "fs_copy",
            json!({ "source": h.path("App/.env"), "destination": h.path("App/env-copy.txt") })
        )
        .await,
        "PROTECTED_RESOURCE"
    );
    // Protected files cannot be modified by default either.
    assert_eq!(
        h.err(
            "fs_write_text",
            json!({ "path": h.path("App/.env"), "content": "x" })
        )
        .await,
        "PROTECTED_RESOURCE"
    );
    // Control data is off limits.
    let settings = h.app.settings_file().display().to_string();
    let (err, v) = h.call("fs_read_text", json!({ "path": settings })).await;
    assert!(err && v["error"]["code"] == "PERMISSION_DENIED", "{v}");
}

// ---------------------------------------------------------------- F, G, H

#[tokio::test]
async fn f_g_external_write_approval_flow() {
    let h = Harness::new().await;
    let target = h.outside.join("config.txt");
    let args = json!({ "path": target.display().to_string(), "content": "v1" });
    // F: deny -> nothing happens.
    let id = h.needs_approval("fs_write_text", args.clone()).await;
    assert!(!target.exists());
    let st = h.ok("approval_status", json!({ "approval_id": id })).await;
    assert_eq!(st["status"], "pending");
    assert_eq!(
        h.err("approval_resume", json!({ "approval_id": id })).await,
        "APPROVAL_PENDING"
    );
    h.core.decide_approval(&id, LocalDecision::Deny).unwrap();
    assert_eq!(
        h.err("approval_resume", json!({ "approval_id": id })).await,
        "APPROVAL_DENIED"
    );
    assert!(!target.exists());

    // G: allow once -> approval alone runs nothing; resume runs exactly the stored op.
    let id = h.needs_approval("fs_write_text", args.clone()).await;
    h.core
        .decide_approval(&id, LocalDecision::AllowOnce)
        .unwrap();
    assert!(!target.exists(), "approval must not execute anything");
    let st = h.ok("approval_status", json!({ "approval_id": id })).await;
    assert_eq!(st["status"], "allowed_once");
    // Concurrent resumes dispatch once.
    let (a, b) = tokio::join!(
        h.call("approval_resume", json!({ "approval_id": id })),
        h.call("approval_resume", json!({ "approval_id": id }))
    );
    assert!(!a.0 && !b.0, "{a:?} {b:?}");
    let executed = [&a.1, &b.1]
        .iter()
        .filter(|v| v["status"] == "executed")
        .count();
    assert_eq!(executed, 1, "exactly one resume dispatches: {a:?} {b:?}");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "v1");
    // Changing the file and resuming again must not re-run the write.
    std::fs::write(&target, "changed").unwrap();
    let again = h.ok("approval_resume", json!({ "approval_id": id })).await;
    assert_eq!(again["already_executed"], true);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "changed");
    // A second mutation asks again.
    h.needs_approval(
        "fs_write_text",
        json!({ "path": target.display().to_string(), "content": "v2" }),
    )
    .await;
}

#[tokio::test]
async fn h_session_scoped_permission() {
    let h = Harness::new().await;
    let dir = h.outside.join("scoped");
    std::fs::create_dir_all(&dir).unwrap();
    let id = h
        .needs_approval(
            "fs_write_text",
            json!({ "path": dir.join("a.txt").display().to_string(), "content": "a" }),
        )
        .await;
    h.core
        .decide_approval(&id, LocalDecision::AllowSession)
        .unwrap();
    h.ok("approval_resume", json!({ "approval_id": id })).await;
    assert!(dir.join("a.txt").exists());
    // Matching writes now succeed without prompting…
    h.ok(
        "fs_write_text",
        json!({ "path": dir.join("b.txt").display().to_string(), "content": "b" }),
    )
    .await;
    // …but not other operations or other folders.
    h.needs_approval(
        "fs_delete",
        json!({ "path": dir.join("b.txt").display().to_string() }),
    )
    .await;
    h.needs_approval(
        "fs_write_text",
        json!({ "path": h.outside.join("other.txt").display().to_string(), "content": "x" }),
    )
    .await;
    let cur = h.ok("session_current", json!({})).await;
    assert_eq!(
        cur["session_approvals"].as_array().unwrap().len(),
        1,
        "{cur}"
    );
    // A different client cannot use the grant.
    let (_, other) = h.new_client("Other Agent");
    let (err, v) = h
        .call_as(
            &other,
            "fs_write_text",
            json!({ "path": dir.join("c.txt").display().to_string(), "content": "c" }),
        )
        .await;
    assert!(!err && v["status"] == "approval_required", "{v}");
    // Ending the session removes the grant.
    h.ok("session_end", json!({})).await;
    h.needs_approval(
        "fs_write_text",
        json!({ "path": dir.join("d.txt").display().to_string(), "content": "d" }),
    )
    .await;
}

#[tokio::test]
async fn approvals_do_not_survive_mcp_restart() {
    let h = Harness::new().await;
    let id = h
        .needs_approval(
            "fs_write_text",
            json!({ "path": h.outside.join("r.txt").display().to_string(), "content": "x" }),
        )
        .await;
    h.core
        .decide_approval(&id, LocalDecision::AllowOnce)
        .unwrap();
    h.core.restart_mcp(true).await.unwrap();
    let code = h.err("approval_resume", json!({ "approval_id": id })).await;
    assert!(
        code == "APPROVAL_INVALIDATED" || code == "NOT_FOUND",
        "{code}"
    );
    assert!(!h.outside.join("r.txt").exists());
}

#[tokio::test]
async fn approval_target_swap_is_detected() {
    let h = Harness::new().await;
    let real = h.outside.join("target");
    let other = h.outside.join("other");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    let path = real.join("x.txt").display().to_string();
    let id = h
        .needs_approval("fs_write_text", json!({ "path": path, "content": "x" }))
        .await;
    h.core
        .decide_approval(&id, LocalDecision::AllowOnce)
        .unwrap();
    // Swap the approved directory for a junction to somewhere else.
    std::fs::remove_dir(&real).unwrap();
    junction(&real, &other);
    assert_eq!(
        h.err("approval_resume", json!({ "approval_id": id })).await,
        "APPROVAL_INVALIDATED"
    );
    assert!(!other.join("x.txt").exists());
}

// ------------------------------------------------------------------ I, J

#[tokio::test]
async fn i_system_install_requires_approval() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let id = h
        .needs_approval(
            "shell_cmd",
            json!({ "command": "npm install -g left-pad", "cwd": h.path("P") }),
        )
        .await;
    let st = h.ok("approval_status", json!({ "approval_id": id })).await;
    assert_eq!(st["status"], "pending");
    h.needs_approval(
        "process_run",
        json!({ "executable": "cargo", "args": ["install", "--help"], "cwd": h.path("P") }),
    )
    .await;
}

#[tokio::test]
async fn j_tasks_use_redirected_temp() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let out = h
        .ok(
            "shell_cmd",
            json!({ "command": "echo %TEMP%& echo %npm_config_cache%", "cwd": h.path("P") }),
        )
        .await;
    let text = out["output"].as_str().unwrap().to_lowercase();
    let cache = h.app.cache_temp_dir.display().to_string().to_lowercase();
    assert!(text.contains(&format!("{cache}\\tasks\\task_")), "{text}");
    assert!(text.contains(&format!("{cache}\\tools\\cmd\\")), "{text}");
}

// -------------------------------------------------------------- K, L, M, N

fn setup_repo(h: &Harness) -> std::path::PathBuf {
    let remote = h.outside.join("remote.git");
    git(
        &h.outside,
        &["init", "--bare", "-b", "main", remote.to_str().unwrap()],
    );
    let repo = h.projects.join("GitProj");
    std::fs::create_dir_all(&repo).unwrap();
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.name", "Test Person"]);
    git(&repo, &["config", "user.email", "test@example.com"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.join("README.md"), "hi\n").unwrap();
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "Initial commit"]);
    git(
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&repo, &["push", "-u", "origin", "main"]);
    git(&repo, &["remote", "set-head", "origin", "main"]);
    repo
}

#[tokio::test]
async fn k_l_m_git_push_policy() {
    let h = Harness::new().await;
    let repo = setup_repo(&h);
    let r = repo.display().to_string();
    let st = h.ok("git_status", json!({ "repo": r })).await;
    assert_eq!(st["clean"], true, "{st}");
    // K: branch push succeeds.
    h.ok(
        "git_branch_create",
        json!({ "repo": r, "name": "feature/login" }),
    )
    .await;
    std::fs::write(repo.join("login.txt"), "x\n").unwrap();
    h.ok("git_add", json!({ "repo": r, "paths": ["login.txt"] }))
        .await;
    let c = h
        .ok(
            "git_commit",
            json!({ "repo": r, "message": "Add login page" }),
        )
        .await;
    assert_eq!(
        c["author"], "Test Person",
        "configured identity preserved: {c}"
    );
    h.ok("git_push", json!({ "repo": r, "set_upstream": true }))
        .await;
    // L: direct push to the default branch prompts.
    h.ok("git_checkout", json!({ "repo": r, "target": "main" }))
        .await;
    std::fs::write(repo.join("direct.txt"), "x\n").unwrap();
    h.ok("git_add", json!({ "repo": r, "paths": ["direct.txt"] }))
        .await;
    h.ok(
        "git_commit",
        json!({ "repo": r, "message": "Direct change" }),
    )
    .await;
    h.needs_approval("git_push", json!({ "repo": r })).await;
    // …also through the shell.
    h.needs_approval(
        "shell_cmd",
        json!({ "command": "git push origin main", "cwd": r }),
    )
    .await;
    // M: force push prompts.
    h.ok(
        "git_checkout",
        json!({ "repo": r, "target": "feature/login" }),
    )
    .await;
    h.needs_approval("git_push", json!({ "repo": r, "force_with_lease": true }))
        .await;
    h.needs_approval(
        "shell_cmd",
        json!({ "command": "git push --force origin feature/login", "cwd": r }),
    )
    .await;
    h.needs_approval(
        "shell_cmd",
        json!({ "command": "git reset --hard HEAD~1", "cwd": r }),
    )
    .await;
    // Protected files are never staged.
    std::fs::write(repo.join(".env"), "SECRET=abc").unwrap();
    assert_eq!(
        h.err("git_add", json!({ "repo": r, "paths": ["."] })).await,
        "PROTECTED_RESOURCE"
    );
}

#[tokio::test]
async fn n_attribution_is_rejected() {
    let h = Harness::new().await;
    let repo = setup_repo(&h);
    let r = repo.display().to_string();
    std::fs::write(repo.join("a.txt"), "a").unwrap();
    h.ok("git_add", json!({ "repo": r, "paths": ["a.txt"] }))
        .await;
    assert_eq!(
        h.err("git_commit", json!({ "repo": r, "message": "Fix bug\n\nCo-Authored-By: Claude <noreply@anthropic.com>" })).await,
        "ATTRIBUTION_BLOCKED"
    );
    assert_eq!(
        h.err(
            "git_branch_create",
            json!({ "repo": r, "name": "claude/fix-bug" })
        )
        .await,
        "ATTRIBUTION_BLOCKED"
    );
    assert_eq!(
        h.err("github_pr_create", json!({ "repo": r, "title": "Fix bug", "body": "🤖 Generated with [Claude Code](https://claude.com/claude-code)" })).await,
        "ATTRIBUTION_BLOCKED"
    );
    assert_eq!(
        h.err(
            "github_issue_comment",
            json!({ "repo": r, "number": 1, "body": "This change was written by ChatGPT." })
        )
        .await,
        "ATTRIBUTION_BLOCKED"
    );
    assert_eq!(
        h.err("shell_cmd", json!({ "command": "git commit -m \"Fix\" --trailer \"Co-authored-by: GitHub Copilot <x@y>\"", "cwd": r })).await,
        "ATTRIBUTION_BLOCKED"
    );
    // Ordinary text naming a vendor for unrelated reasons is fine.
    let c = h
        .ok(
            "git_commit",
            json!({ "repo": r, "message": "Add OpenAI API client wrapper" }),
        )
        .await;
    assert!(c["commit"].is_string());
}

// ---------------------------------------------------------------- O, P, Q

#[tokio::test]
async fn o_long_task_output_and_cancel() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let v = h
        .ok("shell_cmd", json!({ "command": "for /L %i in (1,1,30) do @(echo tick %i & ping -n 2 127.0.0.1 >nul)", "cwd": h.path("P"), "background": true }))
        .await;
    let task = v["task_id"].as_str().unwrap().to_string();
    assert_eq!(v["status"], "running");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let o1 = h.ok("task_output", json!({ "task_id": task })).await;
    assert!(o1["output"].as_str().unwrap().contains("tick 1"), "{o1}");
    let next = o1["next_offset"].as_i64().unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let o2 = h
        .ok("task_output", json!({ "task_id": task, "offset": next }))
        .await;
    assert!(
        !o2["output"].as_str().unwrap().contains("tick 1\r\n"),
        "incremental output: {o2}"
    );
    h.ok("task_cancel", json!({ "task_id": task })).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let t = h.ok("task_get", json!({ "task_id": task })).await;
    assert_eq!(t["status"], "cancelled", "{t}");
}

#[tokio::test]
async fn p_q_multiple_clients_and_revocation() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("A")).unwrap();
    std::fs::create_dir_all(h.projects.join("B")).unwrap();
    let (b_id, b_token) = h.new_client("Agent B");
    h.ok("session_current", json!({})).await;
    let (err, _) = h.call_as(&b_token, "session_current", json!({})).await;
    assert!(!err);
    let status = h.core.ui_status().await;
    assert_eq!(status.sessions.len(), 2);
    // Each client has a task.
    let a_task = h
        .ok(
            "shell_cmd",
            json!({ "command": "ping -n 60 127.0.0.1", "cwd": h.path("A"), "background": true }),
        )
        .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, b) = h
        .call_as(
            &b_token,
            "shell_cmd",
            json!({ "command": "ping -n 60 127.0.0.1", "cwd": h.path("B"), "background": true }),
        )
        .await;
    let b_task = b["task_id"].as_str().unwrap().to_string();
    // Cross-client access is denied.
    let (err, v) = h
        .call_as(&b_token, "task_output", json!({ "task_id": a_task }))
        .await;
    assert!(err && v["error"]["code"] == "TASK_NOT_FOUND", "{v}");
    // Q: revoke A.
    let creds = h.core.auth.list_clients().unwrap();
    let a_cred = creds
        .iter()
        .find(|c| c.client_id == h.client_id)
        .unwrap()
        .credentials[0]
        .credential_id
        .clone();
    h.core.ui_revoke_credential(&a_cred).unwrap();
    let r = h
        .rpc(
            &h.token,
            "tools/call",
            json!({ "name": "session_current", "arguments": {} }),
        )
        .await;
    assert_eq!(r.status(), 401);
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        h.core.tasks.get(&a_task).unwrap().status,
        workstation_executor::TaskStatus::Killed
    );
    assert_eq!(
        h.core.tasks.get(&b_task).unwrap().status,
        workstation_executor::TaskStatus::Running,
        "other clients unaffected"
    );
    h.core.tasks.kill(&b_task).unwrap();
    let _ = b_id;
}

#[tokio::test]
async fn writer_lease_blocks_second_client() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("Shared")).unwrap();
    h.core.index.full_scan().unwrap();
    let (_, b) = h.new_client("Agent B");
    h.ok(
        "fs_write_text",
        json!({ "path": "Shared/a.txt", "content": "a" }),
    )
    .await;
    let (err, v) = h
        .call_as(
            &b,
            "fs_write_text",
            json!({ "path": "Shared/b.txt", "content": "b" }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PROJECT_LOCKED", "{v}");
    // Reads are not blocked.
    let (err, _) = h
        .call_as(&b, "fs_read_text", json!({ "path": "Shared/a.txt" }))
        .await;
    assert!(!err);
}

// -------------------------------------------------------------------- R

#[tokio::test]
async fn r_emergency_stop_latches_across_restart() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let t = h
        .ok(
            "shell_cmd",
            json!({ "command": "ping -n 120 127.0.0.1", "cwd": h.path("P"), "background": true }),
        )
        .await["task_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = h
        .needs_approval(
            "fs_write_text",
            json!({ "path": h.outside.join("es.txt").display().to_string(), "content": "x" }),
        )
        .await;
    h.core.emergency_stop("test").await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(
        h.core.tasks.get(&t).unwrap().status,
        workstation_executor::TaskStatus::Killed
    );
    assert_eq!(h.core.approvals.get(&id).unwrap().status, "cancelled");
    // New calls fail (listener is down).
    assert!(
        h.http
            .get(format!("{}/health", h.base))
            .send()
            .await
            .is_err()
    );
    let status = h.core.ui_status().await;
    assert_eq!(status.state, "emergency_stopped");
    assert!(!status.remote_access);
    // MCP restart does not clear the latch.
    h.core.restart_mcp(false).await.unwrap();
    assert_eq!(h.core.ui_status().await.state, "emergency_stopped");
    // Simulated app relaunch with the same data directory.
    h.core.shutdown().await;
    let s = h.core.settings.get();
    let core2 = workstation_server::Core::start(workstation_server::CoreOptions {
        paths: h.app.clone(),
        install_dir: None,
        settings_override: Some((*s).clone()),
        background: false,
        helper_exe: None,
    })
    .await
    .unwrap();
    assert_eq!(
        core2.state.get(),
        workstation_server::state::ServerState::EmergencyStopped
    );
    assert!(
        core2.enable_remote_access().await.is_err(),
        "enable must not bypass the latch"
    );
    core2.resume_remote_access().await.unwrap();
    assert_eq!(
        core2.state.get(),
        workstation_server::state::ServerState::Ready
    );
    let r = h
        .http
        .get(format!("{}/health", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    core2.shutdown().await;
}

// -------------------------------------------------------------------- U, V

#[tokio::test]
async fn u_cache_temp_boundaries() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let out = h
        .ok(
            "shell_cmd",
            json!({ "command": "echo %TEMP%", "cwd": h.path("P") }),
        )
        .await;
    let own_temp = out["output"]
        .as_str()
        .unwrap()
        .lines()
        .find(|l| l.contains("tasks"))
        .unwrap()
        .trim()
        .to_string();
    // Own task directory: allowed without prompting.
    h.ok(
        "fs_write_text",
        json!({ "path": format!("{own_temp}\\scratch.txt"), "content": "ok" }),
    )
    .await;
    // Another client's task directory: denied.
    let (_, b) = h.new_client("B");
    let (err, v) = h
        .call_as(
            &b,
            "fs_write_text",
            json!({ "path": format!("{own_temp}\\steal.txt"), "content": "x" }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PERMISSION_DENIED", "{v}");
    // Sibling control data: denied.
    let (err, v) = h
        .call(
            "fs_read_text",
            json!({ "path": h.app.control_db().display().to_string() }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PERMISSION_DENIED", "{v}");
    let (err, v) = h.call("fs_write_text", json!({ "path": h.app.config_dir.join("settings.json").display().to_string(), "content": "{}" })).await;
    assert!(err, "{v}");
    // Escaping reparse point inside the cache: resolved and denied.
    let esc = format!("{own_temp}\\escape");
    junction(std::path::Path::new(&esc), &h.app.config_dir);
    let (err, v) = h
        .call(
            "fs_read_text",
            json!({ "path": format!("{esc}\\settings.json") }),
        )
        .await;
    assert!(err && v["error"]["code"] == "PERMISSION_DENIED", "{v}");
}

#[tokio::test]
async fn v_shell_switch_bypasses_only_shell_preflight() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    h.needs_approval(
        "process_run",
        json!({ "executable": "cargo", "args": ["install", "--help"], "cwd": h.path("P") }),
    )
    .await;
    let mut s = (*h.core.settings.get()).clone();
    s.shell_protection.enabled = false;
    h.core.update_settings(s).await.unwrap();
    let v = h
        .ok(
            "process_run",
            json!({ "executable": "cargo", "args": ["install", "--help"], "cwd": h.path("P") }),
        )
        .await;
    assert_eq!(v["status"], "completed", "{v}");
    assert!(v["warnings"].to_string().contains("OFF"), "{v}");
    // Structured policy still applies.
    h.needs_approval(
        "fs_write_text",
        json!({ "path": h.outside.join("x.txt").display().to_string(), "content": "x" }),
    )
    .await;
    let (err, v) = h
        .call("fs_read_text", json!({ "path": "~/.ssh/id_rsa" }))
        .await;
    assert!(err && v["error"]["code"] == "PROTECTED_RESOURCE", "{v}");
    // Structured Git policy is independent of the switch (checked in k_l_m).
    let mut s = (*h.core.settings.get()).clone();
    s.shell_protection.enabled = true;
    h.core.update_settings(s).await.unwrap();
    h.needs_approval(
        "process_run",
        json!({ "executable": "cargo", "args": ["install", "--help"], "cwd": h.path("P") }),
    )
    .await;
}

// -------------------------------------------------------------------- W

#[tokio::test]
async fn w_redaction_and_data_shared_hashes() {
    use sha2::Digest;
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
    std::fs::write(
        h.projects.join("P").join("notes.md"),
        format!("the token is {secret}\n"),
    )
    .unwrap();
    let v = h.ok("fs_read_text", json!({ "path": "P/notes.md" })).await;
    assert!(!v.to_string().contains(secret), "{v}");
    assert!(v["content"].as_str().unwrap().contains("ghp_<redacted>"));
    // Split across output chunks.
    let out = h
        .ok("shell_powershell", json!({ "script": format!("[Console]::Out.Write('token {}'); Start-Sleep -Milliseconds 400; [Console]::Out.WriteLine('{}')", &secret[..12], &secret[12..]), "cwd": h.path("P") }))
        .await;
    assert!(!out.to_string().contains(&secret[12..]), "{out}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let shares = h.core.audit.query_shares(Default::default()).await.unwrap();
    assert!(!shares.is_empty());
    for s in &shares {
        let payload = h
            .core
            .audit
            .share_payload(s.share_event_id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hex::encode(sha2::Sha256::digest(&payload)), s.sha256);
        assert!(!String::from_utf8_lossy(&payload).contains(secret));
    }
    assert!(
        shares.iter().any(|s| s.transmission == "sent"),
        "{shares:?}"
    );
    // Audit records exist and are redacted.
    let events = h.core.audit.query_events(Default::default()).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.tool_name.as_deref() == Some("fs_read_text"))
    );
}

#[tokio::test]
async fn idempotency_keys_prevent_duplicate_writes() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let args = json!({ "path": "P/once.txt", "content": "first", "mode": "append", "idempotency_key": "k-123" });
    h.ok("fs_write_text", args.clone()).await;
    h.ok("fs_write_text", args.clone()).await;
    assert_eq!(
        std::fs::read_to_string(h.projects.join("P").join("once.txt")).unwrap(),
        "first"
    );
    let mut other = args.clone();
    other["content"] = json!("different");
    assert_eq!(h.err("fs_write_text", other).await, "IDEMPOTENCY_CONFLICT");
}

#[tokio::test]
async fn audit_unavailable_refuses_mutations() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    // Simulate audit storage failure by making the database read-only at the SQLite level.
    h.core
        .audit
        .db()
        .write_sync(|c| {
            c.execute_batch("PRAGMA query_only = ON;")?;
            Ok(())
        })
        .unwrap();
    let code = h
        .err(
            "fs_write_text",
            json!({ "path": "P/x.txt", "content": "x" }),
        )
        .await;
    assert_eq!(code, "AUDIT_UNAVAILABLE");
    assert!(!h.projects.join("P").join("x.txt").exists());
    assert!(h.core.ui_status().await.audit_fault.is_some());
}

#[tokio::test]
async fn corrupt_settings_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let app = workstation_core::paths::AppPaths::with_root(dir.path().join("LocalPilot"));
    app.ensure().unwrap();
    std::fs::write(app.settings_file(), "{ definitely not json").unwrap();
    let core = workstation_server::Core::start(workstation_server::CoreOptions {
        paths: app.clone(),
        install_dir: None,
        settings_override: None,
        background: false,
        helper_exe: None,
    })
    .await
    .unwrap();
    assert_eq!(
        core.state.get(),
        workstation_server::state::ServerState::Faulted
    );
    assert!(core.enable_remote_access().await.is_err());
    let d = core.policy().evaluate_fs(
        &dir.path().join("x"),
        workstation_policy::FsAccess::Write,
        &workstation_policy::PolicyContext {
            principal_id: "cl",
            entry: workstation_policy::EntryPoint::Structured,
            session_grants: &[],
            owns_task: &|_| false,
        },
    );
    assert!(matches!(
        d,
        workstation_policy::Decision::Deny {
            code: workstation_core::ErrorCode::ConfigFault,
            ..
        }
    ));
}

#[tokio::test]
async fn credential_commands_blocked_in_shell() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    std::fs::write(h.projects.join("P").join(".env"), "X=1").unwrap();
    for cmd in [
        "gh auth token",
        "git credential fill",
        "type .env",
        "cmdkey /add:x /user:y /pass:z",
    ] {
        let (err, v) = h
            .call("shell_cmd", json!({ "command": cmd, "cwd": h.path("P") }))
            .await;
        let blocked = (err
            && (v["error"]["code"] == "PROTECTED_RESOURCE"
                || v["error"]["code"] == "PERMISSION_DENIED"))
            || v["status"] == "approval_required";
        assert!(blocked, "{cmd}: {v}");
    }
}

#[tokio::test]
async fn secret_environment_is_not_inherited() {
    // SAFETY: set before the core registers the environment; test-local variable.
    unsafe { std::env::set_var("LP_ITEST_SECRET_TOKEN", "itest-secret-value-123") };
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let v = h
        .ok(
            "shell_cmd",
            json!({ "command": "echo [%LP_ITEST_SECRET_TOKEN%]", "cwd": h.path("P") }),
        )
        .await;
    let out = v["output"].as_str().unwrap();
    assert!(out.contains("[%LP_ITEST_SECRET_TOKEN%]"), "{out}");
    assert!(!v.to_string().contains("itest-secret-value-123"));
}

#[tokio::test]
async fn read_limits_and_ranges() {
    let h = Harness::new().await;
    std::fs::create_dir_all(h.projects.join("P")).unwrap();
    let big: String = (1..=100_000).map(|i| format!("line {i}\n")).collect();
    std::fs::write(h.projects.join("P").join("big.txt"), &big).unwrap();
    let v = h.ok("fs_read_text", json!({ "path": "P/big.txt" })).await;
    assert!(
        v["content"].is_null() && v["truncated"] == true,
        "large files return metadata: {}",
        v["message"]
    );
    let v = h
        .ok(
            "fs_read_text",
            json!({ "path": "P/big.txt", "start_line": 10, "end_line": 12 }),
        )
        .await;
    assert_eq!(v["content"], "line 10\nline 11\nline 12\n");
    let v = h
        .ok(
            "fs_read_text",
            json!({ "path": "P/big.txt", "offset": 0, "length": 10 }),
        )
        .await;
    assert_eq!(v["content"], "line 1\nlin");
    assert!(v["next_offset"].is_number());
}

#[tokio::test]
async fn oauth_flow_end_to_end() {
    use base64::Engine;
    use sha2::Digest;
    let h = Harness::new().await;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let redirect = "https://chatgpt.com/connector_platform_oauth_redirect";
    // Dynamic client registration.
    let reg: Value = http
        .post(format!("{}/oauth/register", h.base))
        .json(&json!({ "client_name": "ChatGPT", "redirect_uris": [redirect], "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    // Authorization request with PKCE.
    let verifier = "v".repeat(10) + "abcdefghijklmnopqrstuvwxyz0123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(verifier.as_bytes()));
    let resource = format!("{}/mcp", h.base);
    let mut auth = url::Url::parse(&format!("{}/oauth/authorize", h.base)).unwrap();
    auth.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", redirect)
        .append_pair("state", "st-1")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair(
            "scope",
            "workstation:read workstation:write workstation:execute",
        )
        .append_pair("resource", &resource);
    let r = http.get(auth.clone()).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let consent = format!("{}{}", h.base, r.headers()["location"].to_str().unwrap());
    let page = http
        .get(&consent)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let pending = h.core.ui_pending_connections();
    assert_eq!(pending.len(), 1);
    assert!(
        page.contains(&pending[0].pairing_code),
        "pairing code shown in the browser"
    );
    assert!(pending[0].redirect_is_known_chatgpt);
    // A different browser (no cookie) cannot obtain the code.
    let other = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // Local approval.
    h.core
        .ui_decide_connection(&pending[0].request_id, true, None, Some("ChatGPT".into()))
        .unwrap();
    let r = other.get(&consent).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let r = http.get(&consent).send().await.unwrap();
    assert_eq!(r.status(), 302);
    let loc = url::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    assert!(loc.as_str().starts_with(redirect));
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(q["state"], "st-1");
    assert_eq!(q["iss"], h.base);
    let code = q["code"].clone();
    // Token exchange; wrong verifier fails and burns the code.
    let tok = |form: Vec<(&'static str, String)>| {
        let http = http.clone();
        let url = format!("{}/oauth/token", h.base);
        async move { http.post(url).form(&form).send().await.unwrap() }
    };
    let good = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.clone()),
        ("redirect_uri", redirect.to_string()),
        ("client_id", client_id.clone()),
        ("code_verifier", verifier.clone()),
        ("resource", resource.clone()),
    ];
    let r = tok(good.clone()).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let t: Value = r.json().await.unwrap();
    let access = t["access_token"].as_str().unwrap().to_string();
    let refresh = t["refresh_token"].as_str().unwrap().to_string();
    // The access token works for MCP.
    let (err, v) = h.call_as(&access, "session_current", json!({})).await;
    assert!(!err, "{v}");
    assert_eq!(v["auth_method"], "o_auth");
    assert_eq!(v["client_name"], "ChatGPT");
    let session = v["session_id"].clone();
    // Refresh rotates and keeps the same application session.
    let r = tok(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh.clone()),
        ("client_id", client_id.clone()),
    ])
    .await;
    assert_eq!(r.status(), 200);
    let t2: Value = r.json().await.unwrap();
    let access2 = t2["access_token"].as_str().unwrap().to_string();
    let (_, v2) = h.call_as(&access2, "session_current", json!({})).await;
    assert_eq!(
        v2["session_id"], session,
        "refresh keeps the application session"
    );
    // Reusing the old refresh token revokes the grant.
    let r = tok(vec![
        ("grant_type", "refresh_token".into()),
        ("refresh_token", refresh),
        ("client_id", client_id.clone()),
    ])
    .await;
    assert_eq!(r.status(), 400);
    let r = h
        .rpc(
            &access2,
            "tools/call",
            json!({ "name": "session_current", "arguments": {} }),
        )
        .await;
    assert_eq!(r.status(), 401);
    // Authorization code replay fails (and would revoke anything issued from it).
    assert_eq!(tok(good.clone()).await.status(), 400);
    // Unregistered redirect URIs are refused without redirecting.
    let mut bad = auth.clone();
    bad.query_pairs_mut()
        .clear()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "https://evil.example.com/cb")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    assert_eq!(http.get(bad).send().await.unwrap().status(), 400);
    // Wrong resource is rejected via redirect with iss.
    let mut wrong = auth.clone();
    wrong
        .query_pairs_mut()
        .clear()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", redirect)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("resource", "https://other.example.com/mcp");
    let r = http.get(wrong).send().await.unwrap();
    assert_eq!(r.status(), 302);
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("error=invalid_target")
    );
}

#[tokio::test]
async fn insufficient_scope_triggers_reauth_metadata() {
    let h = Harness::new().await;
    let id = h.core.auth.create_client("Reader", None).unwrap();
    let (_, token) = h
        .core
        .auth
        .create_manual_token(&id, &["workstation:read".into()], None, None)
        .unwrap();
    let r = h
        .rpc(
            &token,
            "tools/call",
            json!({ "name": "fs_write_text", "arguments": { "path": "a.txt", "content": "x" } }),
        )
        .await;
    let body = parse_body(&r.text().await.unwrap());
    assert_eq!(body["result"]["isError"], true);
    let www = body["result"]["_meta"]["mcp/www_authenticate"][0]
        .as_str()
        .unwrap();
    assert!(
        www.contains("error=\"insufficient_scope\"") && www.contains("resource_metadata="),
        "{www}"
    );
}
