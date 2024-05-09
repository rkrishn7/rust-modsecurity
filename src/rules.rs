use std::{ffi::CString, marker::PhantomData, os::raw::c_char, path::Path};

use crate::bindings::types::Rules_t;

use crate::{
    bindings::{Bindings, RawBindings},
    ModSecurityResult,
};

pub struct Rules<B: RawBindings = Bindings> {
    inner: *mut Rules_t,
    _bindings: PhantomData<B>,
}

impl<B: RawBindings> Default for Rules<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: RawBindings> Rules<B> {
    pub fn new() -> Self {
        Self {
            inner: unsafe { B::msc_create_rules_set() },
            _bindings: PhantomData,
        }
    }

    pub fn add_file<P: AsRef<Path>>(&mut self, file: P) -> ModSecurityResult<()> {
        let file = CString::new(file.as_ref().to_str().expect("Invalid file path"))?;

        let mut error: *const i8 = std::ptr::null();
        let result = unsafe { B::msc_rules_add_file(self.inner, file.as_ptr(), &mut error) };

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
            B::msc_rules_dump(self.inner);
        }
    }

    pub(crate) fn inner(&self) -> *mut Rules_t {
        self.inner
    }
}

impl<B: RawBindings> Drop for Rules<B> {
    fn drop(&mut self) {
        unsafe {
            B::msc_rules_cleanup(self.inner);
        }
    }
}
