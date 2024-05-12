use crate::bindings::types::ModSecurityIntervention_t;
use std::{
    ffi::{CStr, CString},
    fmt::Debug,
};

#[derive(Clone)]
pub struct Intervention {
    pub(crate) inner: ModSecurityIntervention_t,
}

impl Debug for Intervention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Intervention")
            .field("status", &self.status())
            .field("pause", &self.pause())
            .field("url", &self.url())
            .field("log", &self.log())
            .field("disruptive", &self.disruptive())
            .finish()
    }
}

impl Intervention {
    pub fn status(&self) -> i32 {
        self.inner.status
    }

    pub fn pause(&self) -> i32 {
        self.inner.pause
    }

    pub fn url(&self) -> Option<&str> {
        if self.inner.url.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(self.inner.url).to_str().ok() }
    }

    pub fn log(&self) -> Option<&str> {
        if self.inner.log.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(self.inner.log).to_str().ok() }
    }

    pub fn disruptive(&self) -> bool {
        self.inner.disruptive != 0
    }
}

impl Drop for Intervention {
    fn drop(&mut self) {
        unsafe {
            if !self.inner.url.is_null() {
                let _ = CString::from_raw(self.inner.url);
            }

            if !self.inner.log.is_null() {
                let _ = CString::from_raw(self.inner.log);
            }
        }
    }
}
