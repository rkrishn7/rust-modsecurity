use std::{ffi::CString, os::raw::c_char, path::Path};

use modsecurity_sys::{
    msc_create_rules_set, msc_rules_add_file, msc_rules_cleanup, msc_rules_dump, Rules_t,
};

use crate::ModSecurityResult;

pub struct Rules {
    inner: *mut Rules_t,
}

impl Default for Rules {
    fn default() -> Self {
        Self::new()
    }
}

impl Rules {
    pub fn new() -> Self {
        Self {
            inner: unsafe { msc_create_rules_set() },
        }
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, file: P) -> ModSecurityResult<()> {
        let file = CString::new(file.as_ref().to_str().expect("Invalid file path"))?;

        let mut error: *const i8 = std::ptr::null();
        let result = unsafe { msc_rules_add_file(self.inner, file.as_ptr(), &mut error) };

        if result < 0 {
            let raw_err_msg = unsafe { CString::from_raw(error as *mut c_char) };

            Err(crate::ModSecurityError::RulesAddFile(
                raw_err_msg.to_string_lossy().into_owned(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn dump(&mut self) {
        unsafe {
            msc_rules_dump(self.inner);
        }
    }

    pub(crate) fn inner(&self) -> *mut Rules_t {
        self.inner
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        unsafe {
            msc_rules_cleanup(self.inner);
        }
    }
}
