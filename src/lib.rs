use std::ffi::CStr;

use modsecurity_sys::{msc_cleanup, msc_init, msc_who_am_i, ModSecurity_t};

mod error;
mod rules;
mod transaction;

pub use error::ModSecurityError;
pub use rules::Rules;
pub use transaction::Transaction;

pub type ModSecurityResult<T> = Result<T, ModSecurityError>;

pub struct ModSecurity {
    inner: *mut ModSecurity_t,
}

impl ModSecurity {
    pub fn new() -> Self {
        Self {
            inner: unsafe { msc_init() },
        }
    }

    pub fn transaction<'a>(&'a self, rules: &'a Rules) -> Transaction<'a> {
        Transaction::new(self, rules, None)
    }

    pub fn whoami(&self) -> String {
        let c_str = unsafe {
            let c_str = msc_who_am_i(self.inner());
            CStr::from_ptr(c_str)
        };

        String::from_utf8_lossy(c_str.to_bytes()).to_string()
    }

    pub fn set_connector_info(&mut self, connector: &str) -> ModSecurityResult<()> {
        let connector = std::ffi::CString::new(connector)?;

        unsafe {
            modsecurity_sys::msc_set_connector_info(self.inner(), connector.as_ptr());
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
            modsecurity_sys::msc_set_log_cb(self.inner(), Some(native_log_cb));
        }
    }

    pub(crate) fn inner(&self) -> *mut ModSecurity_t {
        self.inner
    }
}

impl Drop for ModSecurity {
    fn drop(&mut self) {
        unsafe {
            msc_cleanup(self.inner);
        }
    }
}
