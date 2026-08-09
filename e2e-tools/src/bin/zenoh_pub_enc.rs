use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use slim_common::framing::encode_chunk_frame;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    topic: String,
    #[arg(long)]
    key_hex: String,
    #[arg(long)]
    plain: String,
    /// 段号（默认 0）
    #[arg(long, default_value_t = 0)]
    segment_seq: u32,
    /// 段内起始偏移（默认 0）
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// 探针设备 ID（默认 1）
    #[arg(long, default_value_t = 1)]
    dev_id: u32,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let key_bytes = hex::decode(&cli.key_hex).unwrap();
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce_bytes = [0u8; 12];
    for (i, b) in nonce_bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(1);
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plain_len = cli.plain.len() as u32;
    let mut ciphertext = cli.plain.into_bytes();
    cipher
        .encrypt_in_place(nonce, &[], &mut ciphertext)
        .unwrap();

    // 缺陷 #7 契约：帧负载 = nonce(12) + ChaCha20 密文；头部携带
    // (dev_id, segment_seq, start_offset)，否则 sub_save_test 视为 unframed 丢弃。
    let mut sealed = Vec::with_capacity(12 + ciphertext.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&ciphertext);
    let frame = encode_chunk_frame(cli.dev_id, cli.segment_seq, cli.offset, plain_len, &sealed, false);

    let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    println!("pub enc session open");
    session.put(&cli.topic, &frame).await.unwrap();
    println!(
        "put enc OK: {} ({} bytes, dev={} seg={} off={})",
        cli.topic,
        frame.len(),
        cli.dev_id,
        cli.segment_seq,
        cli.offset
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}
