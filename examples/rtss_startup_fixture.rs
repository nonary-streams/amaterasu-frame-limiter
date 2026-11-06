//! Disposable process-tree fixture. Never packaged or used as an RTSS backend.
use std::{process::Command, time::Duration};

fn main() {
    let mut mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--wait-input" {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        mode.clear();
    }
    let child = if mode.is_empty() {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--descendant")
            .spawn()
            .unwrap();
        std::fs::write("descendant.pid", child.id().to_string()).unwrap();
        Some(child)
    } else {
        None
    };
    std::fs::write(
        if mode == "--descendant" {
            "descendant.ready"
        } else {
            "ready"
        },
        b"ready",
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(30));
    if let Some(mut child) = child {
        child.wait().unwrap();
    }
}
