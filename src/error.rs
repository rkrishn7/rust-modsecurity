//! Error types for ModSecurity

#[derive(Clone, PartialEq, Eq, Debug)]
/// Primary error type for ModSecurity
pub enum ModSecurityError {
    /// Error when converting a string to a C string
    Nul(std::ffi::NulError),
    /// Error when processing a connection
    ProcessConnection,
    /// Error when processing URI
    ProcessUri,
    /// Error when processing logging
    ProcessLogging,
    /// Error when processing the request body
    ProcessRequestBody,
    /// Error when processing the response body
    ProcessResponseBody,
    /// Error when processing the request headers
    ProcessRequestHeaders,
    /// Error when processing the response headers
    ProcessResponseHeaders,
    /// Error when adding a request header
    AddRequestHeader,
    /// Error when adding a response header
    AddResponseHeader,
    /// Error when appending to the request body
    AppendRequestBody,
    /// Error when appending to the response body
    AppendResponseBody,
    /// Error when checking for an intervention
    Intervention,
    /// Error when adding a file to the rule set
    RulesAddFile(String),
    /// Error when adding plain rules to the rule set
    RulesAddPlain(String),
    /// Error when updating the status code
    UpdateStatusCode,
}

impl From<std::ffi::NulError> for ModSecurityError {
    fn from(err: std::ffi::NulError) -> Self {
        ModSecurityError::Nul(err)
    }
}
