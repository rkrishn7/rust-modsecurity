//! ModSecurity transaction API.

use std::{
    ffi::CString,
    marker::PhantomData,
    os::raw::{c_char, c_uchar, c_void},
};

use crate::{
    bindings::{
        types::{ModSecurityIntervention_t, Transaction_t},
        Bindings, RawBindings,
    },
    error::ModSecurityError,
    intervention::Intervention,
    msc::ModSecurity,
    rules::Rules,
    ModSecurityResult,
};

/// An intermediate builder for creating a [`TransactionBuilder`]
pub struct TransactionBuilderWithoutRules<'a, B: RawBindings = Bindings> {
    ms: &'a ModSecurity<B>,
}

impl<'a, B: RawBindings> TransactionBuilderWithoutRules<'a, B> {
    pub(crate) fn new(ms: &'a ModSecurity<B>) -> Self {
        Self { ms }
    }

    /// Creates a new transaction builder with the given rules.
    pub fn with_rules(self, rules: &'a Rules<B>) -> TransactionBuilder<'a, B> {
        TransactionBuilder::new(self.ms, rules)
    }
}

/// Builds a ModSecurity transaction with custom configuration.
pub struct TransactionBuilder<'a, B: RawBindings = Bindings> {
    ms: &'a ModSecurity<B>,
    rules: &'a Rules<B>,
    log_cb: Option<LogCallback>,
    id: Option<&'a str>,
    _bindings: PhantomData<B>,
}

impl<'a, B: RawBindings> TransactionBuilder<'a, B> {
    fn new(ms: &'a ModSecurity<B>, rules: &'a Rules<B>) -> Self {
        Self {
            ms,
            rules,
            log_cb: None,
            id: None,
            _bindings: PhantomData,
        }
    }

    /// Sets a logging callback for the transaction that will be invoked for each generated
    /// log message.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// let rules = Rules::new();
    ///
    /// let transaction = ms.transaction_builder().with_rules(&rules).with_logging(|msg| {
    ///     if let Some(msg) = msg {
    ///         println!("Log: {}", msg);
    ///     }
    /// }).build().expect("error building transaction");
    ///
    /// ```
    pub fn with_logging<F>(mut self, log_cb: F) -> Self
    where
        F: Fn(Option<&str>) + Send + Sync + 'static,
    {
        self.log_cb = Some(Box::new(log_cb));
        self
    }

    /// Sets an explicit transaction ID.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// let rules = Rules::new();
    ///
    /// let transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .with_id("some-unique-id")
    ///     .build()
    ///     .expect("error building transaction");
    /// ```
    pub fn with_id(mut self, id: &'a str) -> Self {
        self.id = Some(id);
        self
    }

    /// Creates the configured transaction.
    pub fn build(self) -> ModSecurityResult<Transaction<'a, B>> {
        let transaction = Transaction::new(self.ms, self.rules, self.id, self.log_cb);
        transaction
    }
}

/// The type of the logging callback that can be set on a [`Transaction`].
pub type LogCallback = Box<dyn Fn(Option<&str>) + Send + Sync + 'static>;

/// A ModSecurity transaction.
///
/// A transaction represents the inspection on an entire request and response cycle.
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

unsafe impl Send for Transaction<'_, Bindings> {}
unsafe impl Sync for Transaction<'_, Bindings> {}

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
        if $result == 1 {
            Ok($ok)
        } else {
            Err($err)
        }
    };
}

impl<'a, B: RawBindings> Transaction<'a, B> {
    pub(crate) fn new(
        ms: &'a ModSecurity<B>,
        rules: &'a Rules<B>,
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

    /// Processes rules in the logging phase for this transaction.
    ///
    /// At this point there is not need to hold the connection, the response can be
    /// delivered prior to the execution of this method.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///     SecRuleEngine On
    ///
    ///     SecRule REQUEST_URI "test" "phase:5,id:'2',t:none,log,deny,status:403,msg:'Access denied'"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .with_logging(|msg| {
    ///         if let Some(msg) = msg {
    ///             println!("Log: {}", msg);
    ///         }
    ///     })
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.process_uri("/test", "GET", "1.1").expect("Error processing URI");
    /// transaction.process_logging().expect("Error processing logging");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_logging(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_logging(self.inner) };

        msc_result!(result, ModSecurityError::ProcessLogging, ())
    }

    /// Performs analysis on the connection.
    ///
    /// This method should be called at very beginning of a request process. It is
    /// expected to be executed prior to the virtual host resolution, when the
    /// connection arrives on the server.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///     SecRuleEngine On
    ///
    ///     SecRule REMOTE_ADDR "@ipMatch 124.123.122.121" "id:35,phase:1,t:none,deny"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .with_logging(|msg| {
    ///         if let Some(msg) = msg {
    ///             println!("Log: {}", msg);
    ///         }
    ///     })
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.process_connection("124.123.122.121", 12345, "127.0.0.1", 80).expect("Error processing connection");
    /// // The request headers must be received in order for rules in phase 1 to be processed
    /// transaction.process_request_headers().expect("Error processing request headers");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
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
            B::msc_process_connection(self.inner, client.as_ptr(), c_port, server.as_ptr(), s_port)
        };

        msc_result!(result, ModSecurityError::ProcessConnection, ())
    }

    /// Perform the analysis on the URI and all the query string variables.
    ///
    /// This method should be called at very beginning of a request process. It is
    /// expected to be executed prior to the virtual host resolution, when the
    /// connection arrives on the server.
    ///
    /// There is no direct connection between this function and any phase of the SecLanguage's phases.
    /// It is something that may occur between SecLanguage phases 1 and 2.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::builder().with_log_callbacks().build();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///     SecRuleEngine On
    ///
    ///     SecRule REQUEST_URI "test" "phase:1,id:'2',t:none,log,deny,status:403,msg:'Access denied'"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .with_logging(|msg| {
    ///         if let Some(msg) = msg {
    ///             println!("Log: {}", msg);
    ///         }
    ///     })
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.process_uri("/test", "GET", "1.1").expect("Error processing URI");
    /// transaction.process_request_headers().expect("Error processing request headers");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_uri(
        &mut self,
        uri: &str,
        method: &str,
        http_version: &str,
    ) -> ModSecurityResult<()> {
        let uri = CString::new(uri)?;
        let protocol = CString::new(method)?;
        let http_version = CString::new(http_version)?;

        let result = unsafe {
            B::msc_process_uri(
                self.inner,
                uri.as_ptr(),
                protocol.as_ptr(),
                http_version.as_ptr(),
            )
        };

        msc_result!(result, ModSecurityError::ProcessUri, ())
    }

    /// Appends a request body to the transaction.
    pub fn append_request_body(&mut self, body: &[u8]) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_append_request_body(self.inner, body.as_ptr(), body.len()) };

        msc_result!(result, ModSecurityError::AppendRequestBody, ())
    }

    /// Appends a response body to the transaction.
    pub fn append_response_body(&mut self, body: &[u8]) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_append_response_body(self.inner, body.as_ptr(), body.len()) };

        msc_result!(result, ModSecurityError::AppendResponseBody, ())
    }

    /// Processes rules in the request body phase for this transaction.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///    SecRuleEngine On
    ///
    ///    SecRule REQUEST_BODY "@rx test" "phase:2,id:'1',t:none,deny"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.append_request_body(b"test").expect("Error appending request body");
    /// transaction.process_request_body().expect("Error processing request body");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_request_body(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_request_body(self.inner) };

        msc_result!(result, ModSecurityError::ProcessRequestBody, ())
    }

    /// Processes rules in the response body phase for this transaction.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///    SecRuleEngine On
    ///
    ///    SecResponseBodyAccess On
    ///
    ///    SecRule RESPONSE_BODY "@rx test" "phase:4,id:'1',t:none,deny"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.append_response_body(b"test").expect("Error appending response body");
    /// transaction.process_response_body().expect("Error processing response body");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_response_body(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_response_body(self.inner) };

        msc_result!(result, ModSecurityError::ProcessResponseBody, ())
    }

    /// Processes rules in the request headers phase for this transaction.
    ///
    /// The request headers should be added using [`Transaction::add_request_header()`] before calling this method.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///    SecRuleEngine On
    ///
    ///    SecRule REQUEST_HEADERS:X-Client-Port "@streq 22" \
    ///        "id:'1',\
    ///        phase:1,\
    ///        t:none,\
    ///        status:403,\
    ///        deny
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.add_request_header("X-Client-Port", "22").expect("Error adding request header");
    /// transaction.process_request_headers().expect("Error processing request headers");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_request_headers(&mut self) -> ModSecurityResult<()> {
        let result = unsafe { B::msc_process_request_headers(self.inner) };

        msc_result!(result, ModSecurityError::ProcessRequestHeaders, ())
    }

    /// Processes rules in the response headers phase for this transaction.
    ///
    /// The response headers should be added using [`Transaction::add_response_header()`] before calling this method.
    ///
    /// **NOTE**: Remember to check for a possible intervention using [`Transaction::intervention()`]
    /// after calling this method.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///    SecRuleEngine On
    ///
    ///    SecRule RESPONSE_HEADERS:X-Secret-Key "@streq leaked-secret-key" \
    ///        "id:'1',\
    ///        phase:3,\
    ///        t:none,\
    ///        status:403,\
    ///        deny
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.add_response_header("X-Secret-Key", "leaked-secret-key").expect("Error adding response header");
    /// transaction.process_response_headers(200, "HTTP 1.2").expect("Error processing response headers");
    ///
    /// assert!(transaction.intervention().is_some());
    /// ```
    pub fn process_response_headers(&mut self, code: i32, protocol: &str) -> ModSecurityResult<()> {
        let protocol = CString::new(protocol)?;

        let result =
            unsafe { B::msc_process_response_headers(self.inner, code, protocol.as_ptr()) };

        msc_result!(result, ModSecurityError::ProcessResponseHeaders, ())
    }

    /// Adds a request header to the transaction.
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

    /// Adds a response header to the transaction.
    pub fn add_response_header(&mut self, key: &str, value: &str) -> ModSecurityResult<()> {
        let key = CString::new(key)?;
        let value = CString::new(value)?;

        let result = unsafe {
            B::msc_add_response_header(
                self.inner,
                key.as_ptr() as *const c_uchar,
                value.as_ptr() as *const c_uchar,
            )
        };

        msc_result!(result, ModSecurityError::AddResponseHeader, ())
    }

    /// Returns an intervention if one is triggered by the transaction.
    ///
    /// An intervention is triggered when a rule is matched and the corresponding action is disruptive.
    ///
    /// ## Examples
    ///
    /// ```
    /// use modsecurity::{ModSecurity, Rules};
    ///
    /// let ms = ModSecurity::default();
    /// let mut rules = Rules::new();
    ///
    /// rules.add_plain(r#"
    ///     SecRuleEngine On
    ///
    ///     SecRule REQUEST_URI "test" "phase:1,id:'2',t:none,log,deny,status:403,msg:'Access denied'"
    /// "#).expect("Error adding rule set");
    ///
    /// let mut transaction = ms
    ///     .transaction_builder()
    ///     .with_rules(&rules)
    ///     .build()
    ///     .expect("Error building transaction");
    ///
    /// transaction.process_uri("/test", "GET", "1.1").expect("Error processing URI");
    /// transaction.process_request_headers().expect("Error processing request headers");
    ///
    /// let intervention = transaction.intervention().expect("Expected intervention");
    ///
    /// assert_eq!(intervention.status(), 403);
    /// assert!(intervention.log().is_some());
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
            Some(Intervention::new(intervention))
        } else {
            None
        }
    }

    /// Returns the length of the request body.
    pub fn get_request_body_length(&mut self) -> usize {
        unsafe { B::msc_get_request_body_length(self.inner) }
    }

    /// Returns the length of the response body.
    pub fn get_response_body_length(&mut self) -> usize {
        unsafe { B::msc_get_response_body_length(self.inner) }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{atomic::AtomicBool, Arc};

    use crate::{msc::ModSecurity, rules::Rules, ModSecurityError};

    pub struct TestBindings;

    #[cfg(not(miri))]
    impl crate::bindings::RawBindings for TestBindings {}

    #[cfg(miri)]
    impl crate::bindings::RawBindings for TestBindings {
        unsafe fn msc_transaction_cleanup(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) {
        }

        unsafe fn msc_intervention(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _intervention: *mut crate::bindings::types::ModSecurityIntervention_t,
        ) -> i32 {
            1
        }

        unsafe fn msc_get_request_body_length(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> usize {
            1
        }

        unsafe fn msc_get_response_body_length(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> usize {
            1
        }

        unsafe fn msc_init() -> *mut modsecurity_sys::ModSecurity {
            std::ptr::null_mut()
        }

        unsafe fn msc_set_connector_info(
            _: *mut modsecurity_sys::ModSecurity,
            _: *const std::os::raw::c_char,
        ) {
        }

        unsafe fn msc_set_log_cb(
            _: *mut modsecurity_sys::ModSecurity,
            _: modsecurity_sys::ModSecLogCb,
        ) {
        }

        unsafe fn msc_cleanup(_: *mut modsecurity_sys::ModSecurity) {}

        unsafe fn msc_new_transaction(
            _msc: *mut modsecurity_sys::ModSecurity,
            _rules: *mut modsecurity_sys::RulesSet,
            _log_cb: *mut std::ffi::c_void,
        ) -> *mut crate::bindings::types::Transaction_t {
            std::ptr::null_mut()
        }

        unsafe fn msc_new_transaction_with_id(
            _msc: *mut modsecurity_sys::ModSecurity,
            _rules: *mut modsecurity_sys::RulesSet,
            _id: *mut std::os::raw::c_char,
            _log_cb: *mut std::ffi::c_void,
        ) -> *mut crate::bindings::types::Transaction_t {
            std::ptr::null_mut()
        }

        unsafe fn msc_create_rules_set() -> *mut crate::bindings::types::Rules_t {
            std::ptr::null_mut()
        }

        unsafe fn msc_rules_add_file(
            _: *mut crate::bindings::types::Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            1
        }

        unsafe fn msc_rules_add(
            _: *mut crate::bindings::types::Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            1
        }

        unsafe fn msc_rules_cleanup(
            _: *mut crate::bindings::types::Rules_t,
        ) -> std::os::raw::c_int {
            1
        }

        unsafe fn msc_rules_dump(_: *mut crate::bindings::types::Rules_t) {}

        unsafe fn msc_process_logging(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_connection(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _client: *const std::os::raw::c_char,
            _c_port: i32,
            _server: *const std::os::raw::c_char,
            _s_port: i32,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_uri(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _uri: *const std::os::raw::c_char,
            _protocol: *const std::os::raw::c_char,
            _http_version: *const std::os::raw::c_char,
        ) -> i32 {
            1
        }

        unsafe fn msc_append_request_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _body: *const std::os::raw::c_uchar,
            _size: usize,
        ) -> i32 {
            1
        }

        unsafe fn msc_append_response_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _body: *const std::os::raw::c_uchar,
            _size: usize,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_request_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_response_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_request_headers(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            1
        }

        unsafe fn msc_process_response_headers(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _code: i32,
            _protocol: *const std::os::raw::c_char,
        ) -> i32 {
            1
        }

        unsafe fn msc_add_request_header(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _key: *const std::os::raw::c_uchar,
            _value: *const std::os::raw::c_uchar,
        ) -> i32 {
            1
        }

        unsafe fn msc_add_response_header(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _key: *const std::os::raw::c_uchar,
            _value: *const std::os::raw::c_uchar,
        ) -> i32 {
            1
        }
    }

    #[test]
    fn test_with_logging_callbacks() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine DetectionOnly

                SecRule REQUEST_URI "test" "phase:1,id:'1',t:none,log,deny,status:403,msg:'Access denied'"
            "#,
            )
            .unwrap();

        let flag = Arc::new(AtomicBool::new(false));

        let mut transaction = ms
            .transaction_builder()
            .with_rules(&rules)
            .with_logging({
                let flag = Arc::clone(&flag);
                move |_| {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .build()
            .unwrap();

        transaction.process_uri("/test", "GET", "1.1").unwrap();
        transaction.process_request_headers().unwrap();

        #[cfg(not(miri))]
        {
            // We're in DetectionOnly mode so there should be no intervention raised
            assert_eq!(transaction.intervention().is_some(), false);
            assert_eq!(flag.load(std::sync::atomic::Ordering::SeqCst), true);
        }
    }

    #[test]
    fn test_logging_enabled_without_callback() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine DetectionOnly

                SecRule REQUEST_URI "test" "phase:1,id:'1',t:none,log,deny,status:403,msg:'Access denied'"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction.process_uri("/test", "GET", "1.1").unwrap();
        transaction.process_request_headers().unwrap();

        // We're in DetectionOnly mode so there should be no intervention raised
        #[cfg(not(miri))]
        assert_eq!(transaction.intervention().is_some(), false);
    }

    #[test]
    fn test_process_logging() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine DetectionOnly

                SecRule REQUEST_URI "test" "phase:1,id:'1',t:none,log,deny,status:403,msg:'Access denied'"
                SecRule REQUEST_URI "test" "phase:5,id:'2',t:none,log,deny,status:403,msg:'Access denied'"
            "#,
            )
            .unwrap();

        let flag = Arc::new(AtomicBool::new(false));

        let mut transaction = ms
            .transaction_builder()
            .with_rules(&rules)
            .with_logging({
                let flag = Arc::clone(&flag);
                move |_| {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .build()
            .unwrap();

        transaction.process_uri("/test", "GET", "1.1").unwrap();
        // The logging phase is always executed
        transaction.process_logging().unwrap();

        #[cfg(not(miri))]
        assert_eq!(flag.load(std::sync::atomic::Ordering::SeqCst), true);
    }

    #[test]
    fn test_process_uri() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRule REQUEST_URI "test" "phase:1,id:'1',t:none,deny"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction.process_uri("/test", "GET", "1.1").unwrap();
        transaction.process_request_headers().unwrap();

        // We're in DetectionOnly mode so there should be no intervention raised
        #[cfg(not(miri))]
        assert_eq!(transaction.intervention().is_some(), true);
    }

    #[test]
    fn test_process_connection() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRule REMOTE_ADDR "@ipMatch 124.123.122.121" "id:35,phase:1,t:none,deny"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction
            .process_connection("124.123.122.121", 0, "127.0.0.1", 80)
            .unwrap();
        transaction.process_request_headers().unwrap();

        #[cfg(not(miri))]
        assert_eq!(transaction.intervention().is_some(), true);
    }

    #[test]
    fn test_request_body() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRequestBodyAccess On

                SecRule REQUEST_BODY "@rx test" "phase:2,id:'1',t:none,deny"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction.append_request_body("test".as_bytes()).unwrap();
        transaction.process_request_headers().unwrap();
        transaction.process_request_body().unwrap();

        #[cfg(not(miri))]
        {
            assert_eq!(transaction.get_request_body_length(), 4);
            assert_eq!(transaction.intervention().is_some(), true);
        }
    }

    #[test]
    fn test_response_body() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();
        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecResponseBodyAccess On

                SecRule RESPONSE_BODY "@rx test" "phase:4,id:'1',t:none,deny"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction.append_response_body("test".as_bytes()).unwrap();
        transaction.process_response_body().unwrap();

        #[cfg(not(miri))]
        {
            assert_eq!(transaction.get_response_body_length(), 4);
            assert_eq!(transaction.intervention().is_some(), true);
        }
    }

    #[test]
    fn test_request_headers() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();

        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRule REQUEST_HEADERS:X-Client-Port "@streq 22" \
                    "id:'1234567',\
                    phase:1,\
                    t:none,\
                    status:403,\
                    deny
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction
            .add_request_header("X-Client-Port", "22")
            .unwrap();
        transaction.process_request_headers().unwrap();

        #[cfg(not(miri))]
        assert_eq!(transaction.intervention().is_some(), true);
    }

    #[test]
    fn test_response_headers() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();

        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRule RESPONSE_HEADERS:X-Leaked-Key "@rx secret" \
                    "id:'1234567',\
                    phase:3,\
                    t:none,\
                    status:500,\
                    deny
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction
            .add_response_header("X-Leaked-Key", "secret-key")
            .unwrap();
        transaction.process_response_headers(500, "GET").unwrap();

        let intervention = transaction.intervention().unwrap();

        #[cfg(not(miri))]
        assert_eq!(intervention.status(), 500);
    }

    #[test]
    pub fn test_intervention_fields() {
        let ms = ModSecurity::<TestBindings>::builder()
            .with_log_callbacks()
            .build();
        let mut rules = Rules::new();

        rules
            .add_plain(
                r#"
                SecRuleEngine On

                SecRule REQUEST_HEADERS:X-Client-Port "@streq 22" \
                    "id:'1234567',\
                    phase:1,\
                    t:none,\
                    status:403,\
                    deny,\
                    msg:'Access denied'"
            "#,
            )
            .unwrap();

        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

        transaction
            .add_request_header("X-Client-Port", "22")
            .unwrap();
        transaction.process_request_headers().unwrap();

        #[cfg(not(miri))]
        {
            let intervention = transaction.intervention().unwrap();
            assert_eq!(intervention.status(), 403);
            assert_eq!(intervention.pause(), 0);
            assert_eq!(intervention.url(), None);
            assert!(matches!(intervention.log(), Some(_)));
            assert_eq!(intervention.disruptive(), true);
        }
    }

    // Simulate failures in the bindings to make sure our error types are
    // correctly propagated
    pub struct FallibleBindings;

    impl crate::bindings::RawBindings for FallibleBindings {
        #[cfg(miri)]
        unsafe fn msc_transaction_cleanup(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) {
        }

        #[cfg(miri)]
        unsafe fn msc_intervention(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _intervention: *mut crate::bindings::types::ModSecurityIntervention_t,
        ) -> i32 {
            0
        }

        #[cfg(miri)]
        unsafe fn msc_get_request_body_length(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> usize {
            0
        }

        #[cfg(miri)]
        unsafe fn msc_get_response_body_length(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> usize {
            0
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

        #[cfg(miri)]
        unsafe fn msc_new_transaction(
            _msc: *mut modsecurity_sys::ModSecurity,
            _rules: *mut modsecurity_sys::RulesSet,
            _log_cb: *mut std::ffi::c_void,
        ) -> *mut crate::bindings::types::Transaction_t {
            std::ptr::null_mut()
        }

        #[cfg(miri)]
        unsafe fn msc_new_transaction_with_id(
            _msc: *mut modsecurity_sys::ModSecurity,
            _rules: *mut modsecurity_sys::RulesSet,
            _id: *mut std::os::raw::c_char,
            _log_cb: *mut std::ffi::c_void,
        ) -> *mut crate::bindings::types::Transaction_t {
            std::ptr::null_mut()
        }

        #[cfg(miri)]
        unsafe fn msc_create_rules_set() -> *mut crate::bindings::types::Rules_t {
            std::ptr::null_mut()
        }

        #[cfg(miri)]
        unsafe fn msc_rules_add_file(
            _: *mut crate::bindings::types::Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            0
        }

        #[cfg(miri)]
        unsafe fn msc_rules_add(
            _: *mut crate::bindings::types::Rules_t,
            _: *const std::os::raw::c_char,
            _: *mut *const std::os::raw::c_char,
        ) -> std::os::raw::c_int {
            0
        }

        #[cfg(miri)]
        unsafe fn msc_rules_cleanup(
            _: *mut crate::bindings::types::Rules_t,
        ) -> std::os::raw::c_int {
            0
        }

        #[cfg(miri)]
        unsafe fn msc_rules_dump(_: *mut crate::bindings::types::Rules_t) {}

        unsafe fn msc_process_logging(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_connection(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _client: *const std::os::raw::c_char,
            _c_port: i32,
            _server: *const std::os::raw::c_char,
            _s_port: i32,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_uri(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _uri: *const std::os::raw::c_char,
            _protocol: *const std::os::raw::c_char,
            _http_version: *const std::os::raw::c_char,
        ) -> i32 {
            0
        }

        unsafe fn msc_append_request_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _body: *const std::os::raw::c_uchar,
            _size: usize,
        ) -> i32 {
            0
        }

        unsafe fn msc_append_response_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _body: *const std::os::raw::c_uchar,
            _size: usize,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_request_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_response_body(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_request_headers(
            _transaction: *mut crate::bindings::types::Transaction_t,
        ) -> i32 {
            0
        }

        unsafe fn msc_process_response_headers(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _code: i32,
            _protocol: *const std::os::raw::c_char,
        ) -> i32 {
            0
        }

        unsafe fn msc_add_request_header(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _key: *const std::os::raw::c_uchar,
            _value: *const std::os::raw::c_uchar,
        ) -> i32 {
            0
        }

        unsafe fn msc_add_response_header(
            _transaction: *mut crate::bindings::types::Transaction_t,
            _key: *const std::os::raw::c_uchar,
            _value: *const std::os::raw::c_uchar,
        ) -> i32 {
            0
        }
    }

    macro_rules! test_sys_failures {
        ($($name:ident $($param:expr),* => $err:pat)*) => {
            $(
                paste::item! {
                    #[test]
                    fn [<test_ $name _failure>]() {
                        let ms = ModSecurity::<FallibleBindings>::default();
                        let rules = Rules::new();

                        let mut transaction = ms.transaction_builder().with_rules(&rules).build().unwrap();

                        assert!(matches!(
                            transaction.$name($($param),*),
                            Err($err)
                        ));
                    }
                }
            )*
        }
    }

    test_sys_failures! {
        process_logging => ModSecurityError::ProcessLogging
        process_connection "", 0, "", 0 => ModSecurityError::ProcessConnection
        process_uri "", "", "" => ModSecurityError::ProcessUri
        append_request_body b"" => ModSecurityError::AppendRequestBody
        append_response_body b"" => ModSecurityError::AppendResponseBody
        process_request_body => ModSecurityError::ProcessRequestBody
        process_response_body => ModSecurityError::ProcessResponseBody
        process_request_headers => ModSecurityError::ProcessRequestHeaders
        process_response_headers 0, "" => ModSecurityError::ProcessResponseHeaders
        add_request_header "", "" => ModSecurityError::AddRequestHeader
        add_response_header "", "" => ModSecurityError::AddResponseHeader
    }
}
