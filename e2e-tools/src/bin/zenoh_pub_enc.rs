use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    topic: String,
    #[arg(long)]
    key_hex: String,
    #[arg(long)]
    plain: String,
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
    let mut plaintext = cli.plain.into_bytes();
    cipher
        .encrypt_in_place(nonce, &[], &mut plaintext)
        .unwrap();
    let mut payload = Vec::new();
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&plaintext);

    let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    println!("pub enc session open");
    session.put(&cli.topic, &payload).await.unwrap();
    println!("put enc OK: {} ({} bytes)", cli.topic, payload.len());
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}
