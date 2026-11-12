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

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn run(store: &std::path::Path, args: &[&str]) -> std::process::Output {
    otp()
        .args(args)
        .env("OTP_SECRETS_FILE", store)
        .output()
        .expect("failed to run otp")
}

#[test]
fn an_hotp_code_advances_the_counter_each_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets");
    // RFC 4226 key, counter 0.
    let o = run(
        &store,
        &["add", "--hotp", "bank", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let codes: Vec<String> = (0..3)
        .map(|_| {
            String::from_utf8(run(&store, &["-q", "bank"]).stdout)
                .unwrap()
                .trim()
                .to_string()
        })
        .collect();
    assert_eq!(codes, ["755224", "287082", "359152"]);
    let text = std::fs::read_to_string(&store).unwrap();
    assert!(text.contains("counter=3"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&store).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // ls --codes does not use up a counter value.
    let ls = String::from_utf8(run(&store, &["ls", "--codes"]).stdout).unwrap();
    assert!(ls.contains("bank") && ls.contains("HOTP"), "{ls}");
    assert!(std::fs::read_to_string(&store)
        .unwrap()
        .contains("counter=3"));
}

#[test]
fn ls_codes_shows_every_totp_code() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets");
    std::fs::write(
        &store,
        "# mine\ngithub:JBSWY3DPEHPK3PXP\nbroken:not-base32!\n",
    )
    .unwrap();
    let ls = String::from_utf8(run(&store, &["ls", "-c"]).stdout).unwrap();
    let line = ls.lines().find(|l| l.starts_with("github")).unwrap();
    let fields: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(fields[1].len(), 6, "{line}");
    assert!(fields[1].chars().all(|c| c.is_ascii_digit()));
    assert!(ls.contains("broken") && ls.contains("(invalid secret)"));
}

#[test]
fn import_reads_qr_images_and_refuses_clashes() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("secrets");
    let img = fixture("otpauth-example.png");
    let o = run(&store, &["import", "--dry-run", img.to_str().unwrap()]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "would add example (Example, alice@example.com)\n"
    );
    assert!(!store.exists());

    let o = run(&store, &["import", img.to_str().unwrap()]);
    assert!(o.status.success());
    let code = String::from_utf8(run(&store, &["-q", "example"]).stdout).unwrap();
    assert_eq!(code.trim().len(), 6);

    // The same name again: nothing is added.
    let migration = fixture("migration-example.png");
    let o = run(&store, &["import", migration.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("already exists"));
    let o = run(
        &store,
        &["import", "--name", "google", migration.to_str().unwrap()],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let text = std::fs::read_to_string(&store).unwrap();
    assert!(
        text.contains(
            "\ngoogle:otpauth://totp/Example%3Aalice%40google.com?secret=JBSWY3DPEHPK3PXP"
        ),
        "{text}"
    );
    // The secret is never printed.
    assert!(!String::from_utf8_lossy(&o.stderr).contains("JBSWY3DP"));
}
