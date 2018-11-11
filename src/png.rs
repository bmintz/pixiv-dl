extern crate crc;

use self::crc::{crc32, Hasher32};

use std::{
    fs,
    io::{self, Write},
    mem, path,
};

static PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
pub static IHDR: &[u8; 4] = b"IHDR";
pub static IDAT: &[u8; 4] = b"IDAT";
pub static IEND: &[u8; 4] = b"IEND";

fn u32_to_bytes(val: u32) -> [u8; 4] {
    unsafe { mem::transmute(val.to_be()) }
}

pub struct Chunk {
    data: Vec<u8>,
    digest: crc32::Digest,
    header: &'static [u8; 4],
}

pub struct Image {
    file: fs::File,
}

impl Chunk {
    pub fn new(header: &'static [u8; 4]) -> Self {
        let mut digest = crc32::Digest::new(crc32::IEEE);
        digest.write(header);
        Self {
            data: Vec::new(),
            digest: digest,
            header: header,
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        self.data.extend(data);
        self.digest.write(data);
    }

    pub fn write_u32(&mut self, data: u32) {
        self.write(&u32_to_bytes(data));
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn checksum(&self) -> u32 {
        self.digest.sum32()
    }
}

impl Image {
    pub fn new(filename: &path::PathBuf) -> io::Result<Self> {
        let mut file = fs::File::create(filename)?;
        file.write(&PNG_SIGNATURE)?;
        Ok(Self { file: file })
    }

    pub fn write(&mut self, chunk: &Chunk) -> io::Result<()> {
        let len = chunk.len() as u32;
        self.file.write(&u32_to_bytes(len))?;
        self.file.write(chunk.header)?;
        self.file.write(chunk.data.as_slice())?;
        self.file.write(&u32_to_bytes(chunk.checksum()))?;
        Ok(())
    }
}
