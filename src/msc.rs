use lazy_static::lazy_static;
use std::sync::Mutex;
use std::{ffi::CStr, marker::PhantomData};

use crate::bindings::{types::ModSecurity_t, Bindings, RawBindings};

use crate::transaction::TransactionBuilderWithoutRules;
use crate::ModSecurityResult;

lazy_static! {
    static ref DESTROY: Mutex<()> = Mutex::new(());
}

pub struct ModSecurityBuilder<B: RawBindings = Bindings> {
    msc: ModSecurity<B>,
}

impl<B: RawBindings> ModSecurityBuilder<B> {
    fn new() -> Self {
        Self {
            msc: ModSecurity::new(),
        }
    }

    pub fn with_connector_info(mut self, connector: &str) -> ModSecurityResult<Self> {
        self.msc.set_connector_info(connector)?;
        Ok(self)
    }

    pub fn with_log_callbacks(mut self) -> Self {
        self.msc.enable_log_callbacks();
        self
    }

    pub fn build(self) -> ModSecurity<B> {
        self.msc
    }
}

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

    pub fn builder() -> ModSecurityBuilder<B> {
        ModSecurityBuilder::new()
    }

    pub fn transaction_builder(&self) -> TransactionBuilderWithoutRules<'_, B> {
        TransactionBuilderWithoutRules::new(self)
    }

    pub fn whoami(&self) -> &str {
        unsafe {
            let raw = B::msc_who_am_i(self.inner());
            std::str::from_utf8_unchecked(CStr::from_ptr(raw).to_bytes())
        }
    }

    fn set_connector_info(&mut self, connector: &str) -> ModSecurityResult<()> {
        let connector = std::ffi::CString::new(connector)?;

        unsafe {
            B::msc_set_connector_info(self.inner(), connector.as_ptr());
        };

        Ok(())
    }

    fn enable_log_callbacks(&mut self) {
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
        let _lock = DESTROY.lock().expect("Poisoned lock");
        unsafe {
            B::msc_cleanup(self.inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ModSecurityError;

    use super::*;

    struct TestBindings;

    impl RawBindings for TestBindings {
        unsafe fn msc_who_am_i(
            _: *mut modsecurity_sys::ModSecurity,
        ) -> *const std::os::raw::c_char {
            "ModSecurity vX.X.X\0".as_ptr() as *const std::os::raw::c_char
        }

        #[cfg(miri)]
        unsafe fn msc_init() -> *mut modsecurity_sys::ModSecurity {
            std::ptr::null_mut()
        }

        #[cfg(miri)]
        unsafe fn msc_set_connector_info(
            _: *mut modsecurity_sys::ModSecurity,
            _: *const std::os::raw::c_char,
        ) {
        }

        #[cfg(miri)]
        unsafe fn msc_set_log_cb(
            _: *mut modsecurity_sys::ModSecurity,
            _: modsecurity_sys::ModSecLogCb,
        ) {
        }

        #[cfg(miri)]
        unsafe fn msc_cleanup(_: *mut modsecurity_sys::ModSecurity) {}
    }

    #[test]
    fn test_modsecurity_whoami() {
        let ms: ModSecurity<TestBindings> = ModSecurity::new();
        assert_eq!(ms.whoami(), "ModSecurity vX.X.X");
    }

    #[test]
    fn test_set_connector_info_valid() {
        let ms = ModSecurity::<TestBindings>::builder().with_connector_info("valid connector info");
        assert!(ms.is_ok());
    }

    #[test]
    fn test_set_connector_info_invalid() {
        let ms =
            ModSecurity::<TestBindings>::builder().with_connector_info("invalid\0connector\0info");
        assert!(matches!(ms, Err(ModSecurityError::Nul(_))));
    }

    #[test]
    fn test_enable_log_callbacks() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        assert_eq!(ms.whoami(), "ModSecurity vX.X.X");
    }

    #[test]
    fn test_transaction_builder() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        assert_eq!(ms.whoami(), "ModSecurity vX.X.X");
    }
}
