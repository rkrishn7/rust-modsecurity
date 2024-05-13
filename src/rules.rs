//! ModSecurity rules.

use lazy_static::lazy_static;
use std::sync::Mutex;
use std::{ffi::CString, marker::PhantomData, os::raw::c_char, path::Path};

use crate::bindings::types::Rules_t;

use crate::{
    bindings::{Bindings, RawBindings},
    ModSecurityResult,
};

lazy_static! {
    /// We use a mutex to serialize rule parsing and cleanup across threads. This is because
    /// the underlying ModSecurity library is not thread-safe in this area as it relies on a
    /// non-reentrant parser.
    ///
    /// More information on this can be found [here](https://github.com/owasp-modsecurity/ModSecurity/issues/3138)
    static ref RULES: Mutex<()> = Mutex::new(());
}

/// A set of rules to be used by a ModSecurity instance.
///
/// ### Considerations
///
/// This type uses a `Mutex` to serialize certain operations - specifically rule parsing and cleanup.
/// This is because the underlying ModSecurity library does not appear to be thread-safe in these areas.
/// More information on this can be found [here](https://github.com/owasp-modsecurity/ModSecurity/issues/3138).
///
/// Because of this, is recommended to create a single instance of [`Rules`] and share it across multiple [`crate::transaction::Transaction`]s.
pub struct Rules<B: RawBindings = Bindings> {
    inner: *mut Rules_t,
    _bindings: PhantomData<B>,
}

impl<B: RawBindings> Default for Rules<B> {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! msc_add_rules_result {
    ($result:ident, $error:ident, $error_ty:expr) => {
        if $result < 0 {
            let error = if $error.is_null() {
                "Unknown error".to_string()
            } else {
                let raw_err_msg = unsafe { CString::from_raw($error as *mut c_char) };
                raw_err_msg.to_string_lossy().into_owned()
            };

            Err($error_ty(error))
        } else {
            Ok(())
        }
    };
}

unsafe impl<B: RawBindings> Send for Rules<B> {}
unsafe impl<B: RawBindings> Sync for Rules<B> {}

impl<B: RawBindings> Rules<B> {
    /// Creates a new set of rules.
    pub fn new() -> Self {
        Self {
            inner: unsafe { B::msc_create_rules_set() },
            _bindings: PhantomData,
        }
    }

    /// Adds rules from a file to the set.
    ///
    /// ## Examples
    ///
    /// ```no_run
    /// use modsecurity::Rules;
    ///
    /// let mut rules = Rules::new();
    /// rules.add_file("/path/to/rules.conf").expect("Failed to add rules from file");
    /// ```
    pub fn add_file<P: AsRef<Path>>(&mut self, file: P) -> ModSecurityResult<()> {
        // SAFETY: Parsing is not thread-safe. So we serialize the calls
        // to this function across instances.
        let _lock: std::sync::MutexGuard<()> = RULES.lock().expect("Poisoned lock");

        let file = CString::new(file.as_ref().to_str().expect("Invalid file path"))?;

        let mut error: *const i8 = std::ptr::null();
        let result = unsafe { B::msc_rules_add_file(self.inner, file.as_ptr(), &mut error) };

        msc_add_rules_result!(result, error, crate::ModSecurityError::RulesAddFile)
    }

    /// Adds plain rules to the set.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::Rules;
    ///
    /// let mut rules = Rules::new();
    /// rules.add_plain("SecRuleEngine On\n").expect("Failed to add rules");
    /// ```
    pub fn add_plain(&mut self, plain_rules: &str) -> ModSecurityResult<()> {
        // SAFETY: Parsing is not thread-safe. So we serialize the calls
        // to this function across instances.
        let _lock = RULES.lock().expect("Poisoned lock");

        let plain_rules = CString::new(plain_rules)?;

        let mut error: *const i8 = std::ptr::null();
        let result = unsafe { B::msc_rules_add(self.inner, plain_rules.as_ptr(), &mut error) };

        msc_add_rules_result!(result, error, crate::ModSecurityError::RulesAddPlain)
    }

    /// Dumps the rules to stdout.
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
        // SAFETY: State associated with parsing is not thread-safe.
        let _lock = RULES.lock().expect("Poisoned lock");
        unsafe {
            B::msc_rules_cleanup(self.inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::ModSecurityError;

    use super::*;
    use tempfile::NamedTempFile;

    struct TestBindings;

    #[cfg(miri)]
    impl RawBindings for TestBindings {
        unsafe fn msc_create_rules_set() -> *mut Rules_t {
            std::ptr::null_mut()
        }

        unsafe fn msc_rules_add_file(
            _: *mut Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            0
        }

        unsafe fn msc_rules_add(
            _: *mut Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            0
        }

        unsafe fn msc_rules_cleanup(_: *mut Rules_t) -> std::os::raw::c_int {
            0
        }

        unsafe fn msc_rules_dump(_: *mut Rules_t) {}
    }

    struct TestFallibleBindings;

    #[cfg(miri)]
    impl RawBindings for TestFallibleBindings {
        unsafe fn msc_create_rules_set() -> *mut Rules_t {
            std::ptr::null_mut()
        }

        unsafe fn msc_rules_add_file(
            _: *mut Rules_t,
            _: *const std::os::raw::c_char,
            e: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            -1
        }

        unsafe fn msc_rules_add(
            _: *mut Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            -1
        }

        unsafe fn msc_rules_cleanup(_: *mut Rules_t) -> std::os::raw::c_int {
            0
        }
    }

    #[cfg(not(miri))]
    impl RawBindings for TestBindings {
        unsafe fn msc_rules_dump(_: *mut Rules_t) {}
    }

    #[cfg(not(miri))]
    impl RawBindings for TestFallibleBindings {
        unsafe fn msc_rules_dump(_: *mut Rules_t) {}
    }

    #[test]
    fn test_rules_add_file_ok() {
        let plain_rules = r#"
            SecRuleEngine On
        "#;
        let mut file = NamedTempFile::new().unwrap();
        file.as_file_mut()
            .write_all(plain_rules.as_bytes())
            .unwrap();

        let mut rules = Rules::<TestBindings>::new();

        assert!(matches!(rules.add_file(file.path()), Ok(())));
    }

    #[test]
    fn test_rules_add_file_parse_err() {
        let plain_rules = r#"
            InvalidDirectiveXXX Yeet
        "#;
        let mut file = NamedTempFile::new().unwrap();
        file.as_file_mut()
            .write_all(plain_rules.as_bytes())
            .unwrap();

        let mut rules = Rules::<TestFallibleBindings>::new();

        assert!(matches!(
            rules.add_file(file.path()),
            Err(ModSecurityError::RulesAddFile(_))
        ));
    }

    #[test]
    fn test_rules_add_file_nonexistent() {
        let mut rules = Rules::<TestFallibleBindings>::new();

        assert!(matches!(
            rules.add_file("/some/invalid/path/that/does/not/exist"),
            Err(ModSecurityError::RulesAddFile(_))
        ));
    }

    #[test]
    fn test_rules_add_plain_ok() {
        let plain_rules = r#"
            SecRuleEngine On
        "#;

        let mut rules = Rules::<TestBindings>::new();

        assert!(matches!(rules.add_plain(plain_rules), Ok(())));
    }

    #[test]
    fn test_rules_add_plain_parse_err() {
        let plain_rules = r#"
            InvalidDirectiveXXX Yeet
        "#;

        let mut rules = Rules::<TestFallibleBindings>::new();

        assert!(matches!(
            rules.add_plain(plain_rules),
            Err(ModSecurityError::RulesAddPlain(_))
        ));
    }

    #[test]
    fn test_rules_dump() {
        let plain_rules = r#"
            SecRuleEngine On
        "#;

        let mut rules = Rules::<TestBindings>::new();

        rules.add_plain(plain_rules).unwrap();

        rules.dump();
    }
}
