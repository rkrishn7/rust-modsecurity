//! ModSecurity instance and builder.

use lazy_static::lazy_static;
use std::sync::Mutex;
use std::{ffi::CStr, marker::PhantomData};

use crate::bindings::{types::ModSecurity_t, Bindings, RawBindings};

use crate::transaction::TransactionBuilderWithoutRules;
use crate::ModSecurityResult;

lazy_static! {
    /// We use a mutex to serialize drops of [`ModSecurity`]. This is because the underlying
    /// ModSecurity library does not appear to be thread-safe in this area.
    ///
    /// More information on this can be found [here](https://github.com/owasp-modsecurity/ModSecurity/issues/3138)
    static ref MSC: Mutex<()> = Mutex::new(());
}

/// Builds a ModSecurity instance with custom configuration.
pub struct ModSecurityBuilder<B: RawBindings = Bindings> {
    msc: ModSecurity<B>,
}

impl<B: RawBindings> ModSecurityBuilder<B> {
    fn new() -> Self {
        Self {
            msc: ModSecurity::default(),
        }
    }

    /// Overrides information about the connector that is using the library.
    ///
    /// By default, the connector info is set to `rust-modsecurity vX.X.X`.
    pub fn with_connector_info(mut self, connector: &str) -> ModSecurityResult<Self> {
        self.msc.set_connector_info(connector)?;
        Ok(self)
    }

    /// Enables log callbacks on the ModSecurity instance. The callbacks themselves are specified when
    /// creating a [`crate::transaction::Transaction`].
    pub fn with_log_callbacks(mut self) -> Self {
        self.msc.enable_log_callbacks();
        self
    }

    /// Creates the configured ModSecurity instance.
    pub fn build(self) -> ModSecurity<B> {
        self.msc
    }
}

/// A ModSecurity instance.
///
/// This is the main entry point to the ModSecurity library. It is used to create transactions and
/// manage the library's configuration.
///
/// ### Considerations
///
/// This type uses a `Mutex` to serialize drops as the underlying ModSecurity library is not thread-safe in this area.
/// More information on this can be found [here](https://github.com/owasp-modsecurity/ModSecurity/issues/3138).
///
/// Because of this, it is recommended to create a single instance of [`ModSecurity`] during a program.
/// In almost all cases, only one instance should be needed.
pub struct ModSecurity<B: RawBindings = Bindings> {
    inner: *mut ModSecurity_t,
    _bindings: PhantomData<B>,
}

impl<B: RawBindings> Default for ModSecurity<B> {
    fn default() -> Self {
        let mut msc = ModSecurity::new();
        msc.set_connector_info(concat!("rust-modsecurity v", env!("CARGO_PKG_VERSION")))
            .expect("Failed to set connector info");
        msc
    }
}

impl<B: RawBindings> ModSecurity<B> {
    fn new() -> Self {
        Self {
            inner: unsafe { B::msc_init() },
            _bindings: PhantomData,
        }
    }

    /// Creates a new ModSecurity builder.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::ModSecurity;
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// ```
    pub fn builder() -> ModSecurityBuilder<B> {
        ModSecurityBuilder::new()
    }

    /// Creates a new transaction builder.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let rules = Rules::new();
    /// let transaction = ms.transaction_builder().with_rules(&rules).build().expect("error building transaction");
    /// ```
    pub fn transaction_builder(&self) -> TransactionBuilderWithoutRules<'_, B> {
        TransactionBuilderWithoutRules::new(self)
    }

    /// Returns information about this ModSecurity version and platform.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::ModSecurity;
    ///
    /// let ms = ModSecurity::default();
    /// println!("ModSecurity version: {}", ms.whoami());
    /// ```
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
        let _lock = MSC.lock().expect("Poisoned lock");
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
