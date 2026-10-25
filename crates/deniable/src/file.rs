//! A volume as a `std::io` file, so existing code that reads and writes
//! files (an app's own vault format, say) can keep its data in a volume.

use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::{BlockDevice, Store, VolumeId};

/// Reads, writes and seeks within one volume. `flush` saves.
pub struct VolumeFile<'a, D: BlockDevice> {
    store: &'a mut Store<D>,
    id: VolumeId,
    pos: u64,
}

impl<'a, D: BlockDevice> VolumeFile<'a, D> {
    pub(crate) fn new(store: &'a mut Store<D>, id: VolumeId) -> Self {
        Self { store, id, pos: 0 }
    }
}

impl<D: BlockDevice> Read for VolumeFile<'_, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.store.read(self.id, self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<D: BlockDevice> Write for VolumeFile<'_, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.store.write(self.id, self.pos, buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(self.store.flush()?)
    }
}

impl<D: BlockDevice> Seek for VolumeFile<'_, D> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let len = self.store.len(self.id)?;
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = pos.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}
