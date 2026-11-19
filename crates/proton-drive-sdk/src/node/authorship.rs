use crate::account::AccountClient;
use crate::author::Author;
use crate::node::crypto::AuthorshipVerificationFailure;
use crate::utils::PotentialObject;
use proton_rpgp::{PrivateKey, PublicKey};
use std::sync::Arc;

pub enum PgpKeyRingOrKey {
    KeyRing(Vec<PublicKey>),
    PrivateKey(PrivateKey),
}

#[derive(Debug, Clone)]
pub struct AuthorshipClaim {
    pub keys: Vec<PublicKey>,
    pub author: Author,
    pub key_retrieval_error_message: Option<String>,
}

impl AuthorshipClaim {
    pub async fn create(
        account_client: Arc<dyn AccountClient>,
        claimed_author_email_address: Option<&str>,
    ) -> Self {
        let email = match claimed_author_email_address {
            None | Some("") => {
                return Self {
                    keys: vec![],
                    author: Author::ANONYMOUS,
                    key_retrieval_error_message: None,
                };
            }
            Some(e) => e,
        };

        match account_client.get_address_public_keys(email).await {
            Ok(keys) => Self {
                keys,
                author: Author {
                    email_address: Some(email.to_string()),
                },
                key_retrieval_error_message: None,
            },
            Err(e) => Self {
                keys: vec![],
                author: Author {
                    email_address: Some(email.to_string()),
                },
                key_retrieval_error_message: Some(e.to_string()),
            },
        }
    }

    /// Returns the public key ring for non-anonymous authors,
    /// or wraps the fallback private key for anonymous authors.
    pub fn get_key_ring(&self, anonymous_fallback_key: &PrivateKey) -> PgpKeyRingOrKey {
        if !self.author.is_anonymous() {
            PgpKeyRingOrKey::KeyRing(self.keys.clone())
        } else {
            PgpKeyRingOrKey::PrivateKey(anonymous_fallback_key.clone())
        }
    }

    /// The claimed author, without verification; see [`Self::to_verified_author`].
    pub fn to_potential_author(
        &self,
    ) -> PotentialObject<Author, crate::protobuf::SignatureVerificationError> {
        PotentialObject::Node(self.author.clone())
    }

    /// The author of something checked against this claim: the claimed author when the
    /// signature verified, else a [`crate::protobuf::SignatureVerificationError`] naming
    /// the claimed author, as the official SDKs keep it on the node
    /// (`AuthorshipClaimExtensions.ToAuthorshipResult`). The item itself stays usable.
    #[allow(deprecated)]
    pub fn to_verified_author(
        &self,
        failure: Option<&AuthorshipVerificationFailure>,
    ) -> PotentialObject<Author, crate::protobuf::SignatureVerificationError> {
        match failure {
            None => PotentialObject::Node(self.author.clone()),
            Some(failure) => {
                PotentialObject::Degraded(crate::protobuf::SignatureVerificationError {
                    claimed_author: Some(crate::protobuf::Author {
                        email_address: self.author.email_address.clone().unwrap_or_default(),
                    }),
                    message: match (&self.key_retrieval_error_message, failure.status) {
                        (Some(error), _) => {
                            format!("Could not verify the author of this item: {error}")
                        }
                        (None, AuthorshipVerificationFailure::NO_VERIFICATION_KEYS) => {
                            "Could not verify the author of this item: no keys".into()
                        }
                        (None, _) => "Could not verify the author of this item".into(),
                    },
                })
            }
        }
    }

    /// The claim a signature is checked against: this author's address keys, or for an
    /// anonymous author `anonymous_keys` (anonymous uploads are signed with the parent
    /// node's key), plus `extra_keys` (a node key that signs its own hash and content
    /// keys), as the official SDKs build their key rings.
    pub fn verification_claim<'a>(
        &self,
        anonymous_keys: impl IntoIterator<Item = &'a crate::pgp::PgpPrivateKey>,
        extra_keys: impl IntoIterator<Item = &'a crate::pgp::PgpPrivateKey>,
    ) -> Self {
        use proton_rpgp::AsPublicKeyRef;
        let mut keys = if self.author.is_anonymous() {
            anonymous_keys
                .into_iter()
                .map(|key| key.0.as_public_key().clone())
                .collect()
        } else {
            self.keys.clone()
        };
        keys.extend(
            extra_keys
                .into_iter()
                .map(|key| key.0.as_public_key().clone()),
        );
        Self {
            keys,
            author: self.author.clone(),
            key_retrieval_error_message: self.key_retrieval_error_message.clone(),
        }
    }

    /// The verification result of a signature checked against this claim: `failure`,
    /// or, when nothing could be checked because a named author's keys could not be
    /// had, a failure: an unverifiable signature is not a verified one.
    pub fn checked(
        &self,
        failure: Option<AuthorshipVerificationFailure>,
    ) -> Option<AuthorshipVerificationFailure> {
        if failure.is_none() && self.keys.is_empty() && !self.author.is_anonymous() {
            return Some(AuthorshipVerificationFailure {
                status: AuthorshipVerificationFailure::NO_VERIFICATION_KEYS,
            });
        }
        failure
    }
}

pub struct NodeAuthorshipClaimProvider;

impl NodeAuthorshipClaimProvider {
    pub async fn get_node_authorship_claim(
        account_client: Arc<dyn AccountClient>,
        link: &crate::api::links::LinkDto,
    ) -> AuthorshipClaim {
        AuthorshipClaim::create(account_client, link.signature_email_address.as_deref()).await
    }

    pub async fn get_content_authorship_claim(
        account_client: Arc<dyn AccountClient>,
        revision: &crate::api::revision::RevisionDto,
    ) -> AuthorshipClaim {
        AuthorshipClaim::create(account_client, revision.signature_email_address.as_deref()).await
    }
}
