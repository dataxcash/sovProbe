use clap::Parser;

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long)]
    topic: String,
    #[arg(long)]
    payload: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let session = zenoh::open(zenoh::Config::default())
        .await
        .expect("zenoh open failed");
    println!("pub session open");
    session
        .put(&cli.topic, cli.payload.as_bytes())
        .await
        .expect("put failed");
    println!("put OK: {}", cli.topic);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}
