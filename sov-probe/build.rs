/// 编译 bpf/capture.bpf.c → target/bpf/{debug,release}/capture.bpf.o
/// 依赖系统 clang + linux 头文件。
fn main() {
    let bpf_c = "bpf/capture.bpf.c";
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    // include_bytes_aligned! 相对 src/capture/mod.rs 用 "../../target/bpf/{profile}/capture.bpf.o"
    let target_bpf = std::path::PathBuf::from(format!("target/bpf/{}", profile));
    std::fs::create_dir_all(&target_bpf).unwrap();
    let out_o = target_bpf.join("capture.bpf.o");

    // 多架构头文件路径（asm/types.h 等），不同发行版位置可能不同
    let multiarch = [
        "/usr/include/x86_64-linux-gnu",
        "/usr/include/aarch64-linux-gnu",
        "/usr/include/arm-linux-gnueabihf",
    ]
    .iter()
    .find(|p| std::path::Path::new(p).exists())
    .map(|s| s.to_string());

    let mut cmd = std::process::Command::new("clang");
    cmd.args(["-O2", "-g", "-target", "bpf", "-c", bpf_c, "-o", out_o.to_str().unwrap()]);
    if let Some(m) = multiarch {
        cmd.arg(format!("-isystem{m}"));
    }
    let status = cmd.status().expect("clang 编译 eBPF 失败，请确认已安装 clang");

    assert!(
        status.success(),
        "clang 编译 capture.bpf.c 失败，详见上方输出"
    );

    println!("cargo:rerun-if-changed={}", bpf_c);
    println!("cargo:rerun-if-env-changed=PROFILE");
}
