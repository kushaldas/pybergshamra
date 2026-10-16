//! Per-document serialization of pybergshamra's own mutating operations.
//!
//! `sign_document` and `sign_enveloped_document` serialize a pyuppsala
//! document, sign the snapshot with the GIL released, and then update the
//! live document. Two such calls on the same document could otherwise both
//! capture the unsigned XML and both splice their signature in, leaving two
//! enveloped signatures that each exclude only themselves and therefore both
//! fail to verify. Each document therefore has one busy flag keyed by its
//! Python object address; a second pybergshamra operation on the same
//! document waits, with the GIL released, until the first has updated it.
//!
//! This covers pybergshamra's own operations only. Mutating a document
//! through pyuppsala (including element proxies) while one of these calls is
//! in progress is the caller's responsibility to avoid, exactly as with any
//! other mutable object shared between threads.

use pyo3::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

struct Slot {
    busy: Mutex<bool>,
    released: Condvar,
}

static REGISTRY: OnceLock<Mutex<HashMap<usize, Weak<Slot>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<usize, Weak<Slot>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Holds a document busy for the lifetime of the guard; dropping it wakes
/// the next waiter. The guard is `Send`, so it can be acquired inside
/// `Python::detach` and carried back under the GIL.
pub struct DocumentGuard {
    slot: Arc<Slot>,
}

impl Drop for DocumentGuard {
    fn drop(&mut self) {
        let mut busy = self
            .slot
            .busy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *busy = false;
        drop(busy);
        self.slot.released.notify_one();
    }
}

/// Reserve `document` for one pybergshamra mutating operation.
///
/// Waiting happens with the GIL released, so a thread that is still holding
/// the document (and is itself detached while signing, or is back under the
/// GIL to splice the result in) can always make progress; the GIL is
/// reacquired before the guard is returned.
pub fn acquire(py: Python<'_>, document: &Bound<'_, PyAny>) -> DocumentGuard {
    let key = document.as_ptr() as usize;
    let slot = {
        let mut map = registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Drop slots whose last guard has gone, so the registry stays bounded
        // by the number of documents currently being operated on.
        map.retain(|_, weak| weak.strong_count() > 0);
        match map.get(&key).and_then(Weak::upgrade) {
            Some(slot) => slot,
            None => {
                let slot = Arc::new(Slot {
                    busy: Mutex::new(false),
                    released: Condvar::new(),
                });
                map.insert(key, Arc::downgrade(&slot));
                slot
            }
        }
    };
    py.detach(move || {
        let mut busy = slot
            .busy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *busy {
            busy = slot
                .released
                .wait(busy)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *busy = true;
        drop(busy);
        DocumentGuard { slot }
    })
}
