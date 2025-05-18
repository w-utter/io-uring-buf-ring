use crate::buf_ring::{BufRing, state};
use io_uring::cqueue::{Entry, EntryMarker};

use core::marker::PhantomData;

pub struct BufferId<'a, 'b, E: EntryMarker> {
    buf: &'a mut BufRing<state::Init>,
    buf_id: u16,
    cqe_res: i32,
    marker: PhantomData<&'b E>,
}

impl<'a, 'b, E: EntryMarker> BufferId<'a, 'b, E> {
    pub(crate) fn new(buf: &'a mut BufRing<state::Init>, cqe: &'b E) -> std::io::Result<Option<Self>> {
        // io_uring doesn't expose its sys bindings
        // so they've been redefined here.
        const IORING_CQE_F_BUFFER: libc::c_uint = 1;
        const IORING_CQE_BUFFER_SHIFT: libc::c_uint = 16;

        let e: Entry = cqe.clone().into();
        let flags = e.flags();
        let cqe_res = e.result();

        if cqe_res < 0 {
            return Err(std::io::Error::from_raw_os_error(-cqe_res));
        }

        let buf_id = if flags & IORING_CQE_F_BUFFER == 0 {
            return Ok(None);
        } else {
            (flags >> IORING_CQE_BUFFER_SHIFT) as u16
        };

        Ok(Some(Self {
            buf,
            buf_id,
            cqe_res,
            marker: PhantomData,
        }))
    }

    /// gives the associated buf ring buffer associated with the CQE entry
    pub fn buffer(&self) -> &[u8] {
        // SAFETY
        // `buf_id` is guaranteed to be a valid index into the buf ring
        // and 0 < `cqe_res` < buf.len()
        unsafe { &self.buf.buffer(self.buf_id)[..(self.cqe_res as _)] }
    }
}

impl<'a, 'b, E: EntryMarker> Drop for BufferId<'a, 'b, E> {
    fn drop(&mut self) {
        unsafe { self.buf.advance(1) }
    }
}

