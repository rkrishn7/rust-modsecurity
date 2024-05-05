use crate::{ModSecurity, ModSecurityResult, Rules};

use modsecurity_sys::{
    msc_add_request_header, msc_intervention, msc_new_transaction, msc_process_logging,
    msc_process_request_body, msc_process_request_headers, ModSecurityIntervention,
    Transaction as ModSecurityTransaction,
};

type LogCallback = Box<dyn Fn(Option<&str>) + Send + Sync + 'static>;

pub struct Transaction<'a> {
    inner: *mut ModSecurityTransaction,
    ms: &'a ModSecurity,
    rules: &'a Rules,
    log_cb: Option<Box<LogCallback>>,
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        unsafe {
            modsecurity_sys::msc_transaction_cleanup(self.inner);
        }
    }
}

impl<'a> Transaction<'a> {
    pub fn new(ms: &'a ModSecurity, rules: &'a Rules, log_cb: Option<LogCallback>) -> Self {
        let log_cb = log_cb.map(|cb| Box::new(cb));
        let log_cb_raw = log_cb
            .as_ref()
            .map(|cb| &**cb as *const _ as *mut std::os::raw::c_void)
            .unwrap_or(std::ptr::null_mut());

        let msc_transaction = unsafe { msc_new_transaction(ms.inner(), rules.inner(), log_cb_raw) };

        // SAFETY: We keep `log_cb` alive as long as the `Transaction` is alive so it's safe to
        // invoke it in the callback.
        Self {
            inner: msc_transaction,
            ms,
            rules,
            log_cb,
        }
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
