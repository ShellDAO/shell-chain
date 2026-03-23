use shell_primitives::Root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TentativeAccepted {
    pub payload_root: Root,
    pub authorization_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationValidated {
    pub payload_root: Root,
    pub signing_root: Root,
    pub verified_authorization_count: usize,
}
