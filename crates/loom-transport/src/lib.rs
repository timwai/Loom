//! Authenticated transport boundary. The secure-channel module remains an experimental PoC.
//! A transport cannot assert authenticity merely because it is connected.

use loom_identity::PeerPrincipal;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    NoVerifiedChannel,
    PathUnavailable,
}

pub trait VerifiedChannel: Send + Sync {
    fn remote_principal(&self) -> &PeerPrincipal;
}

/// No test/fake channel is exported by default.
pub struct DisabledTransport;

impl DisabledTransport {
    pub fn dial(&self) -> Result<(), TransportError> {
        Err(TransportError::NoVerifiedChannel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_is_not_implicitly_trusted() {
        assert_eq!(
            DisabledTransport.dial(),
            Err(TransportError::NoVerifiedChannel)
        );
    }
}

/// Experimental inner TLS 1.3 channel independent of an untrusted Relay bearer.
pub mod secure_channel;
