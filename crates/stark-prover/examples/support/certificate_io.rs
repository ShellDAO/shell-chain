//! Shared bounded, strict and create-new certificate I/O.
use std::{
    error::Error,
    fs::OpenOptions,
    io::{Cursor, Read, Write},
    path::Path,
};
pub fn read(path: &Path, max: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let f = std::fs::File::open(path)?;
    if f.metadata()?.len() > max {
        return Err("certificate input resource bound exceeded".into());
    }
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("certificate input resource bound exceeded".into());
    }
    Ok(bytes)
}
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Box<dyn Error>> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor)?;
    if cursor.position() != bytes.len() as u64 {
        return Err("trailing certificate data".into());
    }
    Ok(value)
}
pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}
pub fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}
