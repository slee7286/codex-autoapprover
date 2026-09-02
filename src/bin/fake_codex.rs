use std::{
    env, fs,
    io::{self, Read},
    process,
};

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.iter().any(|argument| argument == "--version") {
        println!("codex-cli 0.152.1");
        return;
    }

    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .expect("read fake Codex stdin");
    if let Some(path) = env::var_os("FAKE_CODEX_RESULT_FILE") {
        let mut result = arguments.join("\n");
        result.push_str("\n--stdin--\n");
        result.push_str(&stdin);
        fs::write(path, result).expect("write fake Codex result");
    }
    println!("fake-codex-stdout");
    eprintln!("fake-codex-stderr");
    let code = env::var("FAKE_CODEX_EXIT_CODE")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0);
    process::exit(code);
}
