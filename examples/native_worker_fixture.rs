//! Test-only process used by the Windows worker isolation qualification.
//! It performs no RTSS or driver calls and is never included in product packages.
use serde_json::{Value, json};
use std::io::{BufRead, Write};

fn output(value: Value) {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value).unwrap();
    output.write_all(b"\n").unwrap();
    output.flush().unwrap();
}
fn main() {
    let mode = std::env::var("AMATERASU_NATIVE_WORKER_FIXTURE_MODE").unwrap_or_default();
    let mut input = std::io::stdin().lock().lines();
    let config: Value = serde_json::from_str(&input.next().unwrap().unwrap()).unwrap();
    let mut revision = 2;
    output(json!({"kind":"ready","snapshot":{"revision":revision,"targets":[]}}));
    for line in input {
        let call: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let id = call["id"].clone();
        if mode.starts_with("stall") && config["disable_stalled_rtss"] != true {
            if mode == "stall_unknown" {
                std::fs::write(
                    config["rtss_journal"].as_str().unwrap(),
                    b"unrecognized effect journal",
                )
                .unwrap();
            }
            let stage = match mode.as_str() {
                "stall_nvcp" => "nvcp",
                "stall_startup" => "rtss_startup",
                _ => "rtss",
            };
            output(json!({"kind":"stage","id":id,"stage":stage}));
            std::thread::sleep(std::time::Duration::from_secs(30));
        }
        let operation = &call["operation"];
        let value = if operation["kind"] == "lifecycle" {
            let request = &operation["request"];
            let obligations = request["approved_plan"]["obligations"].as_array().unwrap();
            if request["phase"].as_str().unwrap().ends_with("release") {
                json!({"status":"cleanup","outcomes":obligations.iter().map(|obligation| json!({"obligation_id":obligation["obligation_id"],"state":"released"})).collect::<Vec<_>>(),"outputs":[]})
            } else {
                json!({"status":"prepared","candidate":null,"obligations":obligations,"outputs":[]})
            }
        } else {
            json!({"ok":true})
        };
        revision += 1;
        output(
            json!({"kind":"result","id":id,"value":value,"snapshot":{"revision":revision,"targets":[]}}),
        );
    }
}
