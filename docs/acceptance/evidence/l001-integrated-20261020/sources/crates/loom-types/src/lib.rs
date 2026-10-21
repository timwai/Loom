//! Domain identifiers: keep peer, space and resource identifiers distinct.
//! These types do not attest that a digest or ID has been cryptographically verified.

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Constructs an identifier from a *previously computed* 32-byte digest.
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SpaceId([u8; 16]);

impl SpaceId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ResourceId([u8; 16]);

impl ResourceId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Action {
    Read,
    Write,
    Connect,
    Administer,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Connect => "connect",
            Self::Administer => "administer",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_ids_are_not_interchangeable() {
        let peer = PeerId::from_digest([42; 32]);
        let space = SpaceId::from_bytes([42; 16]);
        assert_eq!(peer.digest().len(), 32);
        assert_eq!(space.as_bytes().len(), 16);
        assert_eq!(Action::Administer.to_string(), "administer");
    }
}
