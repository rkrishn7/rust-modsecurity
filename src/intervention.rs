//! Intervention related types and methods.

use crate::bindings::types::ModSecurityIntervention_t;
use std::{
    ffi::{CStr, CString},
    fmt::Debug,
};

/// Represents an intervention from ModSecurity.
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
    /// Returns the status code of the intervention.
    pub fn status(&self) -> i32 {
        self.inner.status
    }

    /// Returns the pause code of the intervention.
    pub fn pause(&self) -> i32 {
        self.inner.pause
    }

    /// Returns the URL, if any, of the intervention.
    pub fn url(&self) -> Option<&str> {
        if self.inner.url.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(self.inner.url).to_str().ok() }
    }

    /// Returns the log message, if any, of the intervention.
    pub fn log(&self) -> Option<&str> {
        if self.inner.log.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(self.inner.log).to_str().ok() }
    }

    /// Returns whether the intervention is disruptive.
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
