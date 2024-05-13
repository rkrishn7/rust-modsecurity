//! Error types for ModSecurity

use core::fmt;
use std::error::Error;

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

impl Error for ModSecurityError {}

impl fmt::Display for ModSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ModSecurityError::Nul(err) => write!(f, "Nul error: {}", err),
            ModSecurityError::ProcessConnection => write!(f, "Error processing connection"),
            ModSecurityError::ProcessUri => write!(f, "Error processing URI"),
            ModSecurityError::ProcessLogging => write!(f, "Error processing logging"),
            ModSecurityError::ProcessRequestBody => write!(f, "Error processing request body"),
            ModSecurityError::ProcessResponseBody => write!(f, "Error processing response body"),
            ModSecurityError::ProcessRequestHeaders => {
                write!(f, "Error processing request headers")
            }
            ModSecurityError::ProcessResponseHeaders => {
                write!(f, "Error processing response headers")
            }
            ModSecurityError::AddRequestHeader => write!(f, "Error adding request header"),
            ModSecurityError::AddResponseHeader => write!(f, "Error adding response header"),
            ModSecurityError::AppendRequestBody => write!(f, "Error appending to request body"),
            ModSecurityError::AppendResponseBody => write!(f, "Error appending to response body"),
            ModSecurityError::Intervention => write!(f, "Error checking for intervention"),
            ModSecurityError::RulesAddFile(err) => {
                write!(f, "Error adding file to rule set: {}", err)
            }
            ModSecurityError::RulesAddPlain(err) => {
                write!(f, "Error adding plain rules to rule set: {}", err)
            }
            ModSecurityError::UpdateStatusCode => write!(f, "Error updating status code"),
        }
    }
}

impl From<std::ffi::NulError> for ModSecurityError {
    fn from(err: std::ffi::NulError) -> Self {
        ModSecurityError::Nul(err)
    }
}
