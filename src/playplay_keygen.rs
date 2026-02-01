use anyhow::Context;

#[derive(Clone)]
pub struct PlayPlayKeygen;

impl PlayPlayKeygen {
    pub fn new(_pe_path: &str) -> anyhow::Result<Self> {
        anyhow::bail!("playplay keygen not implemented in this Rust port");
    }

    pub fn configure(&mut self, _file_id: &[u8], _obfuscated_key: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("playplay keygen not implemented in this Rust port");
    }

    pub fn decrypt_stream<I>(&self, _source: I) -> impl Iterator<Item = Vec<u8>>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        std::iter::empty()
    }

    pub fn playplay_token(&self) -> &[u8] {
        &[]
    }
}
