//! Where a container's blocks are kept: a file, a raw partition or memory.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::BLOCK;

/// Fixed-size blocks that can be read and written in place.
pub trait BlockDevice {
    /// How many blocks there are. Never changes.
    fn blocks(&self) -> u64;
    fn read(&mut self, index: u64, buf: &mut [u8; BLOCK]) -> io::Result<()>;
    fn write(&mut self, index: u64, buf: &[u8; BLOCK]) -> io::Result<()>;
    /// Returns once everything written so far is on the disk.
    fn sync(&mut self) -> io::Result<()>;
}

/// A container in a file, or on a raw partition opened as a file.
pub struct FileDevice {
    file: File,
    blocks: u64,
}

impl FileDevice {
    /// Makes a new file of `blocks` blocks. Format it before use: until then
    /// it holds zeros, which look like nothing but an empty file.
    pub fn create(path: &Path, blocks: u64) -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).create_new(true).open(path)?;
        file.set_len(blocks * BLOCK as u64)?;
        Ok(Self { file, blocks })
    }

    /// Opens an existing file or partition. A size that isn't a whole number
    /// of blocks leaves the remainder unused.
    pub fn open(path: &Path) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        // Seeking to the end also measures a partition, whose metadata says 0.
        let len = file.seek(SeekFrom::End(0))?;
        Ok(Self { file, blocks: len / BLOCK as u64 })
    }
}

impl BlockDevice for FileDevice {
    fn blocks(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, index: u64, buf: &mut [u8; BLOCK]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index * BLOCK as u64))?;
        self.file.read_exact(buf)
    }

    fn write(&mut self, index: u64, buf: &[u8; BLOCK]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index * BLOCK as u64))?;
        self.file.write_all(buf)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}

/// A container held in memory, for tests or for a container that's been
/// read whole and will be written back by the caller.
pub struct MemDevice {
    bytes: Vec<u8>,
}

impl MemDevice {
    /// `blocks` blocks of zeros. Format it before use.
    pub fn new(blocks: u64) -> Self {
        Self { bytes: vec![0; blocks as usize * BLOCK] }
    }

    /// Takes over an existing container's bytes. A remainder smaller than a
    /// block is ignored.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Self {
        bytes.truncate(bytes.len() / BLOCK * BLOCK);
        Self { bytes }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl BlockDevice for MemDevice {
    fn blocks(&self) -> u64 {
        (self.bytes.len() / BLOCK) as u64
    }

    fn read(&mut self, index: u64, buf: &mut [u8; BLOCK]) -> io::Result<()> {
        let at = index as usize * BLOCK;
        let block = self.bytes.get(at..at + BLOCK).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"))?;
        buf.copy_from_slice(block);
        Ok(())
    }

    fn write(&mut self, index: u64, buf: &[u8; BLOCK]) -> io::Result<()> {
        let at = index as usize * BLOCK;
        let block = self.bytes.get_mut(at..at + BLOCK).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "past the end"))?;
        block.copy_from_slice(buf);
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}
