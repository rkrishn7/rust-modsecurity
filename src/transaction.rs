use std::{
    ffi::{CStr, CString},
    fmt::Debug,
    marker::PhantomData,
    os::raw::{c_char, c_uchar, c_void},
};

use crate::{
    bindings::{
        types::{ModSecurityIntervention_t, Transaction_t},
        Bindings, RawBindings,
    },
    msc::ModSecurity,
    ModSecurityError, ModSecurityResult, Rules,
};

pub struct TransactionBuilder<'a, B: RawBindings = Bindings> {
    ms: &'a ModSecurity<B>,
    rules: &'a Rules,
    log_cb: Option<LogCallback>,
    id: Option<&'a str>,
    _bindings: PhantomData<B>,
}

impl<'a, B: RawBindings> TransactionBuilder<'a, B> {
    pub(crate) fn new(ms: &'a ModSecurity<B>, rules: &'a Rules) -> Self {
        Self {
            ms,
            rules,
            log_cb: None,
            id: None,
            _bindings: PhantomData,
        }
    }

    pub fn with_logging<F>(mut self, log_cb: F) -> Self
    where
        F: Fn(Option<&str>) + Send + Sync + 'static,
    {
        self.log_cb = Some(Box::new(log_cb));
        self
    }

    pub fn with_id(mut self, id: &'a str) -> Self {
        self.id = Some(id);
        self
    }

    pub fn build(self) -> ModSecurityResult<Transaction<'a, B>> {
        let transaction = Transaction::new(self.ms, self.rules, self.id, self.log_cb);
        transaction
    }
}

type LogCallback = Box<dyn Fn(Option<&str>) + Send + Sync + 'static>;

pub struct Transaction<'a, B: RawBindings = Bindings> {
    inner: *mut Transaction_t,
    /// This field ensures that the lifetime of `Transaction` is tied to the `ModSecurity` and `Rules`
    /// instances that it was created from. We pack in B and 'a here even though they are unreleated.
    _phantom: PhantomData<&'a B>,
    /// We store the callback here to ensure it's kept alive for the lifetime of the `Transaction`
    /// instance. Along with the lifetime constraints on this struct, this ensures that the callback
    /// can be safely invoked.
    _log_cb: Option<Box<LogCallback>>,
    /// Optional explicit transaction ID
    _id: Option<*mut c_char>,
}

impl<B: RawBindings> Drop for Transaction<'_, B> {
    fn drop(&mut self) {
        unsafe {
            B::msc_transaction_cleanup(self.inner);
            if let Some(id) = self._id {
                let _ = CString::from_raw(id);
            }
        }
    }
}

macro_rules! msc_result {
    ($result:expr, $err:expr, $ok:expr) => {
        if $result < 0 {
            return Err($err);
        } else {
            Ok($ok)
        }
    };
}

impl<'a, B: RawBindings> Transaction<'a, B> {
    pub(crate) fn new(
        ms: &'a ModSecurity<B>,
        rules: &'a Rules,
        id: Option<&str>,
        log_cb: Option<LogCallback>,
    ) -> ModSecurityResult<Self> {
        // NOTE: The double indirection is required here as `Box<dyn Trait>` is a fat pointer and
        // we must be able to convert to it from `*mut c_void`
        let log_cb = log_cb.map(|cb| Box::new(cb));

        let log_cb_raw = log_cb
            .as_ref()
            .map(|cb| &**cb as *const _ as *mut c_void)
            .unwrap_or(std::ptr::null_mut());

        let (maybe_id, msc_transaction) = unsafe {
            if let Some(id) = id {
                let id = CString::new(id)?.into_raw();
                (
                    Some(id),
                    B::msc_new_transaction_with_id(ms.inner(), rules.inner(), id, log_cb_raw),
                )
            } else {
                (
                    None,
                    B::msc_new_transaction(ms.inner(), rules.inner(), log_cb_raw),
                )
            }
        };

        // SAFETY: We need to keep `log_cb` alive as long as the `Transaction` is alive so it's safe to
        // invoke in the callback
        Ok(Self {
            inner: msc_transaction,
            _log_cb: log_cb,
            _phantom: PhantomData,
            _id: maybe_id,
        })
    }

    pub fn process_logging(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_logging(self.inner) };

        msc_result!(result, ModSecurityError::ProcessLogging, ())
    }

    pub fn process_connection(
        &mut self,
        client: &str,
        c_port: i32,
        server: &str,
        s_port: i32,
    ) -> ModSecurityResult<()> {
        let client = CString::new(client)?;
        let server = CString::new(server)?;

        let result = unsafe {
            modsecurity_sys::msc_process_connection(
                self.inner,
                client.as_ptr(),
                c_port,
                server.as_ptr(),
                s_port,
            )
        };

        msc_result!(result, ModSecurityError::ProcessConnection, ())
    }

    pub fn process_request_body(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_request_body(self.inner) };

        msc_result!(result, ModSecurityError::ProcessRequestBody, ())
    }

    pub fn process_request_headers(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_request_headers(self.inner) };

        msc_result!(result, ModSecurityError::ProcessRequestHeaders, ())
    }

    pub fn add_request_header(&mut self, key: &str, value: &str) -> ModSecurityResult<()> {
        let key = CString::new(key)?;
        let value = CString::new(value)?;

        let result = unsafe {
            B::msc_add_request_header(
                self.inner,
                key.as_ptr() as *const c_uchar,
                value.as_ptr() as *const c_uchar,
            )
        };

        msc_result!(result, ModSecurityError::AddRequestHeader, ())
    }

    pub fn intervention(&mut self) -> Option<Intervention> {
        let mut intervention = ModSecurityIntervention_t {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut() as *mut c_char,
            log: std::ptr::null_mut() as *mut c_char,
            disruptive: 0,
        };

        let result = unsafe { B::msc_intervention(self.inner, &mut intervention) };

        if result > 0 {
            Some(Intervention {
                inner: intervention,
            })
        } else {
            None
        }
    }

    pub fn update_status_code(&mut self, status: i32) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_update_status_code(self.inner, status) };

        msc_result!(result, ModSecurityError::UpdateStatusCode, ())
    }
}

#[derive(Clone)]
pub struct Intervention {
    inner: ModSecurityIntervention_t,
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
