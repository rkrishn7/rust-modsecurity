use std::marker::PhantomData;

use crate::{ModSecurity, ModSecurityResult, Rules};

use modsecurity_sys::{
    msc_add_request_header, msc_intervention, msc_new_transaction, msc_new_transaction_with_id,
    msc_process_logging, msc_process_request_body, msc_process_request_headers,
    msc_update_status_code, ModSecurityIntervention, Transaction as ModSecurityTransaction,
};

pub struct TransactionBuilder<'a> {
    ms: &'a ModSecurity,
    rules: &'a Rules,
    log_cb: Option<LogCallback>,
    id: Option<&'a str>,
}

impl<'a> TransactionBuilder<'a> {
    pub(crate) fn new(ms: &'a ModSecurity, rules: &'a Rules) -> Self {
        Self {
            ms,
            rules,
            log_cb: None,
            id: None,
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

    pub fn build(self) -> ModSecurityResult<Transaction<'a>> {
        let transaction = Transaction::new(self.ms, self.rules, self.id, self.log_cb);
        transaction
    }
}

type LogCallback = Box<dyn Fn(Option<&str>) + Send + Sync + 'static>;

pub struct Transaction<'a> {
    inner: *mut ModSecurityTransaction,
    /// This field ensures that the lifetime of `Transaction` is tied to the `ModSecurity` and `Rules`
    /// instances that it was created from.
    _phantom: PhantomData<&'a ()>,
    /// We store the callback here to ensure it's kept alive for the lifetime of the `Transaction`
    /// instance. Along with the lifetime constraints on this struct, this ensures that the callback
    /// can be safely invoked.
    _log_cb: Option<Box<LogCallback>>,
    /// Optional explicit transaction ID
    _id: Option<*mut std::os::raw::c_char>,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        unsafe {
            modsecurity_sys::msc_transaction_cleanup(self.inner);
            if let Some(id) = self._id {
                let _ = std::ffi::CString::from_raw(id);
            }
        }
    }
}

impl<'a> Transaction<'a> {
    pub(crate) fn new(
        ms: &'a ModSecurity,
        rules: &'a Rules,
        id: Option<&str>,
        log_cb: Option<LogCallback>,
    ) -> ModSecurityResult<Self> {
        // NOTE: The double indirection is required here as `Box<dyn Trait>` is a fat pointer and
        // we must be able to convert to it from `*mut c_void`
        let log_cb = log_cb.map(|cb| Box::new(cb));

        let log_cb_raw = log_cb
            .as_ref()
            .map(|cb| &**cb as *const _ as *mut std::os::raw::c_void)
            .unwrap_or(std::ptr::null_mut());

        let (maybe_id, msc_transaction) = unsafe {
            if let Some(id) = id {
                let id = std::ffi::CString::new(id)?.into_raw();
                (
                    Some(id),
                    msc_new_transaction_with_id(ms.inner(), rules.inner(), id, log_cb_raw),
                )
            } else {
                (
                    None,
                    msc_new_transaction(ms.inner(), rules.inner(), log_cb_raw),
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
        let result = unsafe { msc_process_logging(self.inner) };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessLogging)
        } else {
            Ok(())
        }
    }

    pub fn process_connection(
        &mut self,
        client: &str,
        c_port: i32,
        server: &str,
        s_port: i32,
    ) -> ModSecurityResult<()> {
        let client = std::ffi::CString::new(client)?;
        let server = std::ffi::CString::new(server)?;

        let result = unsafe {
            modsecurity_sys::msc_process_connection(
                self.inner,
                client.as_ptr(),
                c_port,
                server.as_ptr(),
                s_port,
            )
        };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessConnection)
        } else {
            Ok(())
        }
    }

    pub fn process_request_body(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { msc_process_request_body(self.inner) };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessRequestBody)
        } else {
            Ok(())
        }
    }

    pub fn process_request_headers(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { msc_process_request_headers(self.inner) };

        if result < 0 {
            Err(crate::ModSecurityError::ProcessRequestHeaders)
        } else {
            Ok(())
        }
    }

    pub fn add_request_header(&mut self, key: &str, value: &str) -> ModSecurityResult<()> {
        let key = std::ffi::CString::new(key)?;
        let value = std::ffi::CString::new(value)?;

        let result = unsafe {
            msc_add_request_header(
                self.inner,
                key.as_ptr() as *const std::os::raw::c_uchar,
                value.as_ptr() as *const std::os::raw::c_uchar,
            )
        };

        if result < 0 {
            Err(crate::ModSecurityError::AddRequestHeader)
        } else {
            Ok(())
        }
    }

    pub fn intervention(&mut self) -> Option<Intervention> {
        let mut intervention = ModSecurityIntervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut() as *mut std::os::raw::c_char,
            log: std::ptr::null_mut() as *mut std::os::raw::c_char,
            disruptive: 0,
        };
        let result = unsafe { msc_intervention(self.inner, &mut intervention) };

        if result > 0 {
            Some(Intervention::from(intervention))
        } else {
            None
        }
    }

    pub fn update_status_code(&mut self, status: i32) -> ModSecurityResult<()> {
        let result = unsafe { msc_update_status_code(self.inner, status) };

        if result < 0 {
            Err(crate::ModSecurityError::UpdateStatusCode)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct Intervention {
    pub status: i32,
    pub url: Option<String>,
    pub log: Option<String>,
    pub disruptive: bool,
}

impl From<ModSecurityIntervention> for Intervention {
    fn from(intervention: modsecurity_sys::ModSecurityIntervention) -> Self {
        let url = if intervention.url.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(intervention.url) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };

        let log = if intervention.log.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(intervention.log) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };

        Self {
            status: intervention.status,
            url,
            log,
            disruptive: intervention.disruptive != 0,
        }
    }
}
