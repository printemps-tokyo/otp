//! Integration tests that exercise the compiled `otp` binary.

use std::process::Command;

fn otp() -> Command {
    Command::new(env!("CARGO_BIN_EXE_otp"))
}

#[test]
fn empty_service_query_is_rejected_before_resolution() {
    let dir = std::env::temp_dir().join("otp-cli-test-empty-query");
    std::fs::create_dir_all(&dir).expect("failed to create temp dir");
    let store = dir.join("secrets");
    std::fs::write(&store, "github:JBSWY3DP\naws:JBSWY3DP\n").expect("failed to write store");

    for query in ["", "   "] {
        let out = otp()
            .arg(query)
            .env("OTP_SECRETS_FILE", &store)
            .output()
            .expect("failed to run otp");
        assert!(
            !out.status.success(),
            "query {query:?} should be rejected, not treated as ambiguous"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("service name required"), "stderr: {stderr}");
        // The error must not leak the whole store as candidate names.
        assert!(!stderr.contains("github"), "stderr: {stderr}");
    }
}
