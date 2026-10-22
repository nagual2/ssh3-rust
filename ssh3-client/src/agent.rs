#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

#[cfg(unix)]
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
#[cfg(unix)]
use ssh3_auth::{Ssh3JwtAlgorithm, build_bearer_token_with_signer};

use crate::{Ssh3ClientConfig, Ssh3ClientError};

#[cfg(unix)]
const SSH_AGENT_FAILURE: u8 = 5;
#[cfg(unix)]
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
#[cfg(unix)]
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
#[cfg(unix)]
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
#[cfg(unix)]
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
#[cfg(unix)]
const SSH_AGENT_RSA_SHA2_256: u32 = 2;

#[derive(Clone, Debug)]
pub enum Ssh3AgentSelection {
    First,
    PublicKey(PathBuf),
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct AgentIdentity {
    key_blob: Vec<u8>,
    public_key: PublicKey,
}

#[cfg(unix)]
struct SshAgentClient {
    stream: UnixStream,
}

pub fn build_agent_bearer_token(
    config: &Ssh3ClientConfig,
    selection: &Ssh3AgentSelection,
    username: &str,
    conversation_id: &[u8; 32],
) -> Result<String, Ssh3ClientError> {
    #[cfg(unix)]
    {
        let socket_path = resolve_agent_socket_path(config)?;
        let mut agent = SshAgentClient::connect(&socket_path)?;
        let identity = agent.select_identity(selection)?;
        build_bearer_token_with_signer(
            &identity.public_key,
            username,
            conversation_id,
            |jwt_algorithm, signing_input| {
                let signature = agent.sign(
                    &identity.key_blob,
                    signing_input,
                    agent_sign_flags(jwt_algorithm)?,
                )?;
                jwt_signature_from_agent_signature(jwt_algorithm, &signature)
            },
        )
    }

    #[cfg(not(unix))]
    {
        let _ = (config, selection, username, conversation_id);
        Err(Ssh3ClientError::AgentUnavailable)
    }
}

#[cfg(unix)]
pub(crate) fn resolve_agent_socket_path(
    config: &Ssh3ClientConfig,
) -> Result<PathBuf, Ssh3ClientError> {
    config
        .agent_socket
        .clone()
        .or_else(|| env::var_os("SSH_AUTH_SOCK").map(PathBuf::from))
        .ok_or(Ssh3ClientError::AgentUnavailable)
}

#[cfg(not(unix))]
pub(crate) fn resolve_agent_socket_path(
    _config: &Ssh3ClientConfig,
) -> Result<PathBuf, Ssh3ClientError> {
    Err(Ssh3ClientError::AgentUnavailable)
}

#[cfg(unix)]
impl SshAgentClient {
    fn connect(path: &Path) -> Result<Self, Ssh3ClientError> {
        Ok(Self {
            stream: UnixStream::connect(path).map_err(Ssh3ClientError::Io)?,
        })
    }

    fn select_identity(
        &mut self,
        selection: &Ssh3AgentSelection,
    ) -> Result<AgentIdentity, Ssh3ClientError> {
        let identities = self.list_identities()?;
        match selection {
            Ssh3AgentSelection::First => identities
                .into_iter()
                .find(|identity| is_supported_agent_key(&identity.public_key))
                .ok_or(Ssh3ClientError::AgentKeyNotFound),
            Ssh3AgentSelection::PublicKey(path) => {
                let expected = load_agent_public_key(path)?;
                let expected_blob = expected.to_bytes().map_err(Ssh3ClientError::SshKey)?;
                let identity = identities
                    .into_iter()
                    .find(|identity| identity.key_blob == expected_blob)
                    .ok_or(Ssh3ClientError::AgentKeyNotFound)?;
                if !is_supported_agent_key(&identity.public_key) {
                    return Err(Ssh3ClientError::UnsupportedAgentKey(
                        identity.public_key.algorithm().as_str().to_string(),
                    ));
                }
                Ok(identity)
            }
        }
    }

    fn list_identities(&mut self) -> Result<Vec<AgentIdentity>, Ssh3ClientError> {
        self.write_message(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        let response = self.read_message()?;
        let mut cursor = response.as_slice();
        match read_byte(&mut cursor)? {
            SSH_AGENT_IDENTITIES_ANSWER => {
                let count = read_u32(&mut cursor)? as usize;
                let mut identities = Vec::with_capacity(count);
                for _ in 0..count {
                    let key_blob = read_ssh_string(&mut cursor)?;
                    let _comment = read_ssh_string(&mut cursor)?;
                    identities.push(AgentIdentity {
                        public_key: PublicKey::from_bytes(&key_blob)
                            .map_err(Ssh3ClientError::SshKey)?,
                        key_blob,
                    });
                }
                if !cursor.is_empty() {
                    return Err(Ssh3ClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in SSH agent identities reply",
                    )));
                }
                Ok(identities)
            }
            SSH_AGENT_FAILURE => Err(Ssh3ClientError::AgentKeyNotFound),
            other => Err(Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SSH agent reply type {other}"),
            ))),
        }
    }

    fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Signature, Ssh3ClientError> {
        let mut payload = vec![SSH_AGENTC_SIGN_REQUEST];
        append_ssh_string(&mut payload, key_blob);
        append_ssh_string(&mut payload, data);
        payload.extend_from_slice(&flags.to_be_bytes());
        self.write_message(&payload)?;

        let response = self.read_message()?;
        let mut cursor = response.as_slice();
        match read_byte(&mut cursor)? {
            SSH_AGENT_SIGN_RESPONSE => {
                let signature_blob = read_ssh_string(&mut cursor)?;
                if !cursor.is_empty() {
                    return Err(Ssh3ClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing bytes in SSH agent sign reply",
                    )));
                }
                Signature::try_from(signature_blob.as_slice()).map_err(Ssh3ClientError::SshKey)
            }
            SSH_AGENT_FAILURE => Err(Ssh3ClientError::AgentKeyNotFound),
            other => Err(Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected SSH agent sign reply type {other}"),
            ))),
        }
    }

    fn write_message(&mut self, payload: &[u8]) -> Result<(), Ssh3ClientError> {
        let len = u32::try_from(payload.len()).map_err(|_| {
            Ssh3ClientError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SSH agent payload exceeds u32 length",
            ))
        })?;
        self.stream
            .write_all(&len.to_be_bytes())
            .map_err(Ssh3ClientError::Io)?;
        self.stream.write_all(payload).map_err(Ssh3ClientError::Io)
    }

    fn read_message(&mut self) -> Result<Vec<u8>, Ssh3ClientError> {
        let mut len = [0u8; 4];
        self.stream
            .read_exact(&mut len)
            .map_err(Ssh3ClientError::Io)?;
        let len = u32::from_be_bytes(len) as usize;
        let mut payload = vec![0u8; len];
        self.stream
            .read_exact(&mut payload)
            .map_err(Ssh3ClientError::Io)?;
        Ok(payload)
    }
}

#[cfg(unix)]
fn load_agent_public_key(path: &Path) -> Result<PublicKey, Ssh3ClientError> {
    PublicKey::read_openssh_file(path)
        .or_else(|_| {
            PrivateKey::read_openssh_file(path).map(|private_key| private_key.public_key().clone())
        })
        .or_else(|_| {
            let pub_path = PathBuf::from(format!("{}.pub", path.display()));
            PublicKey::read_openssh_file(&pub_path)
        })
        .map_err(Ssh3ClientError::SshKey)
}

#[cfg(unix)]
fn is_supported_agent_key(public_key: &PublicKey) -> bool {
    matches!(
        public_key.algorithm(),
        Algorithm::Ed25519 | Algorithm::Rsa { .. }
    )
}

#[cfg(unix)]
fn agent_sign_flags(jwt_algorithm: Ssh3JwtAlgorithm) -> Result<u32, Ssh3ClientError> {
    match jwt_algorithm {
        Ssh3JwtAlgorithm::EdDsa => Ok(0),
        Ssh3JwtAlgorithm::Rs256 => Ok(SSH_AGENT_RSA_SHA2_256),
        Ssh3JwtAlgorithm::Es256 => Err(Ssh3ClientError::UnsupportedAgentKey(
            "ecdsa-sha2-nistp256".to_string(),
        )),
    }
}

#[cfg(unix)]
fn jwt_signature_from_agent_signature(
    jwt_algorithm: Ssh3JwtAlgorithm,
    signature: &Signature,
) -> Result<Vec<u8>, Ssh3ClientError> {
    match jwt_algorithm {
        Ssh3JwtAlgorithm::EdDsa => {
            if signature.algorithm() != Algorithm::Ed25519 {
                return Err(Ssh3ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH agent returned the wrong Ed25519 signature algorithm",
                )));
            }
            Ok(signature.as_bytes().to_vec())
        }
        Ssh3JwtAlgorithm::Rs256 => {
            if signature.algorithm()
                != (Algorithm::Rsa {
                    hash: Some(HashAlg::Sha256),
                })
            {
                return Err(Ssh3ClientError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSH agent returned the wrong RSA signature algorithm",
                )));
            }
            Ok(signature.as_bytes().to_vec())
        }
        Ssh3JwtAlgorithm::Es256 => Err(Ssh3ClientError::UnsupportedAgentKey(
            "ecdsa-sha2-nistp256".to_string(),
        )),
    }
}

#[cfg(unix)]
fn append_ssh_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(unix)]
fn read_byte(cursor: &mut &[u8]) -> Result<u8, Ssh3ClientError> {
    let Some((&byte, rest)) = cursor.split_first() else {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent message",
        )));
    };
    *cursor = rest;
    Ok(byte)
}

#[cfg(unix)]
fn read_u32(cursor: &mut &[u8]) -> Result<u32, Ssh3ClientError> {
    if cursor.len() < 4 {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent u32",
        )));
    }
    let (prefix, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_be_bytes(prefix.try_into().unwrap()))
}

#[cfg(unix)]
fn read_ssh_string(cursor: &mut &[u8]) -> Result<Vec<u8>, Ssh3ClientError> {
    let len = read_u32(cursor)? as usize;
    if cursor.len() < len {
        return Err(Ssh3ClientError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated SSH agent string",
        )));
    }
    let (value, rest) = cursor.split_at(len);
    *cursor = rest;
    Ok(value.to_vec())
}
