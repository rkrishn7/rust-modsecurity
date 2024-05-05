use std::path::Path;

use modsecurity_sys::{
    msc_create_rules_set, msc_rules_add_file, msc_rules_cleanup, msc_rules_dump, Rules_t,
};

use crate::ModSecurityResult;

pub struct Rules {
    inner: *mut Rules_t,
}

impl Rules {
    pub fn new() -> Self {
        Self {
            inner: unsafe { msc_create_rules_set() },
        }
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, file: P) -> ModSecurityResult<()> {
        let file = std::ffi::CString::new(file.as_ref().to_str().expect("Invalid file path"))?;

        let error = std::ffi::CString::new("")?.into_raw() as *mut *const i8;
        let result = unsafe { msc_rules_add_file(self.inner, file.as_ptr(), error) };

        if result < 0 {
            let raw_err_msg = unsafe { std::ffi::CString::from_raw(*error as *mut i8) };

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
