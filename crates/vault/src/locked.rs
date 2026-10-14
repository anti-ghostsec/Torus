//! Keeps the vault's key out of the swap file.
//!
//! Memory an operating system is short of gets written to disk, unencrypted,
//! and can stay there long after the program has gone. The key is held at
//! one fixed address that the system is asked never to write out, and is
//! overwritten when it is no longer needed.

use zeroize::{Zeroize, Zeroizing};

pub(crate) struct LockedKey(Box<[u8; 32]>);

impl LockedKey {
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        // On the heap, so that moving this value never moves the key itself.
        let held = Box::new(*key);
        lock(held.as_ptr(), held.len());
        Self(held)
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.0.zeroize();
        unlock(self.0.as_ptr(), self.0.len());
    }
}

// Locking is a request the system may turn down, for instance when a limit
// on locked memory is reached. The vault works either way.

#[cfg(windows)]
fn lock(at: *const u8, len: usize) {
    unsafe {
        let _ = windows::Win32::System::Memory::VirtualLock(at.cast(), len);
    }
}

#[cfg(windows)]
fn unlock(at: *const u8, len: usize) {
    unsafe {
        let _ = windows::Win32::System::Memory::VirtualUnlock(at.cast(), len);
    }
}

#[cfg(unix)]
fn lock(at: *const u8, len: usize) {
    unsafe {
        libc::mlock(at.cast(), len);
    }
}

#[cfg(unix)]
fn unlock(at: *const u8, len: usize) {
    unsafe {
        libc::munlock(at.cast(), len);
    }
}

#[cfg(not(any(windows, unix)))]
fn lock(_at: *const u8, _len: usize) {}

#[cfg(not(any(windows, unix)))]
fn unlock(_at: *const u8, _len: usize) {}
