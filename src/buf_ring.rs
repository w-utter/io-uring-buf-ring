use io_uring::types::BufRingEntry;
use std::sync::atomic::{AtomicU16, Ordering};

pub(crate) mod state {
    pub struct Uninit;
    pub struct Registered;
    pub struct Init;
}

use core::marker::PhantomData;

pub struct BufRing<State> {
    base: *mut BufRingEntry,
    entries: u32,
    buf_size: u32,
    mask: u32,
    bgid: u16,
    buffer_base: *const u8,
    state: PhantomData<State>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct MapOpts {
    pub privacy: MapPrivacy,
    pub populate: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum MapPrivacy {
    #[default]
    Private,
    Shared,
}

impl BufRing<state::Uninit> {
    pub fn new(entries: u16, buf_size: u32, bgid: u16) -> std::io::Result<Self> {
        Self::new_with_opts(entries, buf_size, bgid, Default::default())
    }

    pub fn new_with_opts(
        mut entries: u16,
        buf_size: u32,
        bgid: u16,
        opts: MapOpts,
    ) -> std::io::Result<Self> {
        if entries == 0 || entries == u16::MAX {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }

        if !entries.is_power_of_two() {
            entries = entries.next_power_of_two()
        }
        let mask = entries - 1;

        let mut map_flags = libc::MAP_ANONYMOUS;

        map_flags |= match opts.privacy {
            MapPrivacy::Private => libc::MAP_PRIVATE,
            MapPrivacy::Shared => libc::MAP_SHARED,
        };

        if opts.populate {
            map_flags |= libc::MAP_POPULATE;
        }

        let buf_ring_size =
            entries as usize * (buf_size as usize + core::mem::size_of::<BufRingEntry>());
        let raw_base = unsafe {
            match libc::mmap(
                std::ptr::null_mut(),
                buf_ring_size,
                libc::PROT_READ | libc::PROT_WRITE,
                map_flags,
                -1,
                0,
            ) {
                libc::MAP_FAILED => return Err(std::io::Error::last_os_error()),
                addr => addr,
            }
        };

        let base = raw_base as *mut BufRingEntry;

        let buffer_base: *const u8 = unsafe {
            raw_base.offset(entries as isize * std::mem::size_of::<BufRingEntry>() as isize)
                as *const u8
        };

        unsafe {
            let tail = BufRingEntry::tail(base);
            let _ = AtomicU16::from_ptr(tail as _).store(0, Ordering::Relaxed);
        }

        Ok(Self {
            base,
            entries: entries as u32,
            buf_size,
            mask: mask as u32,
            bgid,
            buffer_base,
            state: PhantomData,
        })
    }

    pub fn set_bgid(&mut self, bgid: u16) {
        self.bgid = bgid;
    }

    pub fn register(
        self,
        submitter: &io_uring::Submitter<'_>,
    ) -> Result<BufRing<state::Registered>, (std::io::Error, Self)> {
        if let Err(e) =
            unsafe { submitter.register_buf_ring(self.ring_addr(), self.entries(), self.bgid()) }
        {
            return Err((e, self));
        }
        let Self {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            ..
        } = self;

        Ok(BufRing {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            state: PhantomData,
        })
    }
}

impl BufRing<state::Registered> {
    pub fn unregister(
        self,
        submitter: &io_uring::Submitter<'_>,
    ) -> Result<BufRing<state::Uninit>, (std::io::Error, Self)> {
        unsafe { self.unregister_(submitter) }
    }

    pub fn init(mut self) -> BufRing<state::Init> {
        let entries = self.entries();

        for i in 0..entries {
            unsafe { self.add(i, i) };
        }

        unsafe { self.advance_(entries) };

        let Self {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            ..
        } = self;

        BufRing {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            state: PhantomData,
        }
    }
}

impl BufRing<state::Init> {
    pub fn unregister(
        self,
        submitter: &io_uring::Submitter<'_>,
    ) -> Result<BufRing<state::Uninit>, (std::io::Error, Self)> {
        unsafe { self.unregister_(submitter) }
    }

    pub fn buffer_id_from_cqe<'a, 'b, E: io_uring::cqueue::EntryMarker>(
        &'a mut self,
        cqe: &'b E,
    ) -> Option<BufferId<'a, 'b, E>> {
        BufferId::new(self, cqe)
    }

    /// # Safety
    ///
    /// The caller must ensure that `offset` is < `self.entries()`
    pub unsafe fn entry(&self, offset: u16) -> *const BufRingEntry {
        unsafe {
            self.base.offset(offset as isize)
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that `buf_id` is < `self.entries()`
    pub unsafe fn buffer(&self, buf_id: u16) -> &[u8] {
        unsafe {
            let buf = self.get_buffer(buf_id);
            core::slice::from_raw_parts(buf, self.buf_size as usize)
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that an entry has been written into the buf ring.
    pub unsafe fn advance(&mut self, count: u16) {
        unsafe {
            self.advance_(count)
        }
    }
}

use crate::buffer_id::BufferId;

impl<S> BufRing<S> {
    /// # Safety
    ///
    /// The caller must ensure that `buf_id` and `buf_offset` is < `self.entries()`
    #[inline]
    unsafe fn add(&mut self, buf_id: u16, buf_offset: u16) {
        unsafe {
            let offset = (self.tail() + buf_offset as u32) & self.mask;

            let entry = &mut *self.base.offset(offset as isize);

            entry.set_addr(self.get_buffer(buf_id) as u64);
            entry.set_len(self.buf_size);
            entry.set_bid(buf_id);
        };
    }

    /// # Safety
    ///
    /// The caller must ensure `buf_id` < `self.entries()`
    #[inline]
    unsafe fn get_buffer(&self, buf_id: u16) -> *const u8 {
        unsafe {
            self.buffer_base
                .offset((buf_id as u32 * self.buf_size) as isize)
        }
    }

    /// # Safety
    ///
    /// This function should not be called before the buf ring is registered
    #[inline]
    pub(crate) unsafe fn advance_(&mut self, count: u16) {
        unsafe {
            let tail = BufRingEntry::tail(self.base);
            let _ = AtomicU16::from_ptr(tail as _).fetch_add(count, Ordering::Relaxed);
        }
    }

    pub fn entries(&self) -> u16 {
        self.entries as u16
    }

    pub fn ring_addr(&self) -> u64 {
        self.base as u64
    }

    pub fn bgid(&self) -> u16 {
        self.bgid
    }

    pub unsafe fn tail(&self) -> u32 {
        unsafe {
            *BufRingEntry::tail(self.base) as u32
        }
    }

    /// # Safety
    ///
    /// The caller must ensure that the buf ring is registered
    unsafe fn unregister_(
        self,
        submitter: &io_uring::Submitter<'_>,
    ) -> Result<BufRing<state::Uninit>, (std::io::Error, Self)> {
        if let Err(e) = submitter.unregister_buf_ring(self.bgid()) {
            return Err((e, self));
        }

        let Self {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            ..
        } = self;

        Ok(BufRing {
            base,
            entries,
            buf_size,
            mask,
            bgid,
            buffer_base,
            state: PhantomData,
        })
    }
}

impl<S> Drop for BufRing<S> {
    fn drop(&mut self) {
        let buf_ring_size =
            self.entries as usize * (self.buf_size as usize + core::mem::size_of::<BufRingEntry>());

        unsafe {
            libc::munmap(self.base.cast(), buf_ring_size);
        }
    }
}
