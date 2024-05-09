use std::{ffi::CStr, marker::PhantomData};

use crate::bindings::{types::ModSecurity_t, Bindings, RawBindings};

use crate::rules::Rules;
use crate::transaction::TransactionBuilder;
use crate::ModSecurityResult;

pub struct ModSecurity<B: RawBindings = Bindings> {
    inner: *mut ModSecurity_t,
    _bindings: PhantomData<B>,
}

impl<B: RawBindings> Default for ModSecurity<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: RawBindings> ModSecurity<B> {
    pub fn new() -> Self {
        Self {
            inner: unsafe { B::msc_init() },
            _bindings: PhantomData,
        }
    }

    pub fn transaction_builder<'a>(&'a self, rules: &'a Rules) -> TransactionBuilder<'a, B> {
        TransactionBuilder::new(self, rules)
    }

    pub fn whoami(&self) -> String {
        let c_str = unsafe {
            let c_str = B::msc_who_am_i(self.inner());
            CStr::from_ptr(c_str)
        };

        String::from_utf8_lossy(c_str.to_bytes()).to_string()
    }

    pub fn set_connector_info(&mut self, connector: &str) -> ModSecurityResult<()> {
        let connector = std::ffi::CString::new(connector)?;

        unsafe {
            B::msc_set_connector_info(self.inner(), connector.as_ptr());
        };

        Ok(())
    }

    pub fn enable_log_callbacks(&mut self) {
        unsafe extern "C" fn native_log_cb(
            cb: *mut std::os::raw::c_void,
            msg: *const ::std::os::raw::c_void,
        ) {
            let data = msg as *const std::os::raw::c_char;
            let c_str = if data.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(data) })
            };
            let str_slice = c_str.map(|s| s.to_str().expect("Invalid UTF-8 string"));
            if !cb.is_null() {
                let cb = cb as *const *const (dyn Fn(Option<&str>) + Send + Sync + 'static);
                (**cb)(str_slice);
            }
        }

        unsafe {
            B::msc_set_log_cb(self.inner(), Some(native_log_cb));
        }
    }

    pub(crate) fn inner(&self) -> *mut ModSecurity_t {
        self.inner
    }
}

impl<B: RawBindings> Drop for ModSecurity<B> {
    fn drop(&mut self) {
        unsafe {
            B::msc_cleanup(self.inner);
        }
    }
}
