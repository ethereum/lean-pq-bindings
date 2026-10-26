#![doc = include_str!("../README.md")]

use std::fmt;
use std::sync::{Mutex, Once};

use leanvm::{AggregateVerifyError, AggregationError, EthereumProof};

/// A 256-bit message hash, the only message shape either scheme signs.
pub const MESSAGE_LEN: usize = 32;
pub type Message = [u8; MESSAGE_LEN];

/// The public key length of both schemes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Code rate `2^-LOG_INV_RATE` of every proof this crate produces.
const LOG_INV_RATE: usize = 2;

/// Upstream's `aggregate` must not run concurrently within one process.
static PROVER: Mutex<()> = Mutex::new(());
static SETUP: Once = Once::new();

/// Builds the aggregation guest and its tables. Idempotent; [`aggregate`] and
/// [`Aggregate::from_bytes`] call it themselves, so calling it only moves that cost earlier.
pub fn setup() {
    SETUP.call_once(leanvm::setup_prover);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// An input does not have its fixed length.
    InvalidLength {
        what: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A leanSPHINCS kept height above [`sphincs::MAX_KEPT_HEIGHT`].
    InvalidKeptHeight(usize),
    XmssSign(leanvm::lean_xmss::LeanXmssSignError),
    XmssVerify(leanvm::lean_xmss::LeanXmssVerifyError),
    SphincsSign(leanvm::lean_sphincs::LeanSphincsSignError),
    SphincsVerify(leanvm::lean_sphincs::LeanSphincsVerifyError),
    /// The raw leanXMSS signature at this input index does not verify.
    InvalidXmssSignature {
        index: usize,
    },
    /// The raw leanSPHINCS signature at this input index does not verify.
    InvalidSphincsSignature {
        index: usize,
    },
    /// Proving an aggregate failed.
    Aggregation(AggregationError),
    /// An aggregate is malformed or its proof does not verify.
    InvalidAggregate(AggregateVerifyError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                what,
                expected,
                actual,
            } => write!(f, "{what} must be {expected} bytes, got {actual}"),
            Self::InvalidKeptHeight(height) => write!(
                f,
                "leanSPHINCS kept height {height} exceeds {}",
                sphincs::MAX_KEPT_HEIGHT
            ),
            Self::XmssSign(error) => write!(f, "leanXMSS signing failed: {error}"),
            Self::XmssVerify(error) => write!(f, "invalid leanXMSS signature: {error}"),
            Self::SphincsSign(error) => write!(f, "leanSPHINCS signing failed: {error}"),
            Self::SphincsVerify(error) => write!(f, "invalid leanSPHINCS signature: {error}"),
            Self::InvalidXmssSignature { index } => {
                write!(f, "leanXMSS signature {index} does not verify")
            }
            Self::InvalidSphincsSignature { index } => {
                write!(f, "leanSPHINCS signature {index} does not verify")
            }
            Self::Aggregation(error) => write!(f, "aggregation failed: {error}"),
            Self::InvalidAggregate(error) => write!(f, "invalid aggregate: {error}"),
        }
    }
}

impl std::error::Error for Error {}

fn fixed<const N: usize>(what: &'static str, bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::InvalidLength {
        what,
        expected: N,
        actual: bytes.len(),
    })
}

/// leanXMSS: stateful, two XMSS layers of height 16, so `2^32` leaf indices per key.
pub mod xmss {
    use super::{fixed, Error, Message};
    use leanvm::lean_xmss as upstream;

    pub use upstream::LeafIndex;

    pub const SEED_LEN: usize = upstream::SEED_LEN;
    /// Secret key bytes are the key's seed.
    pub const SECRET_KEY_LEN: usize = upstream::SEED_LEN;
    pub const SIGNATURE_LEN: usize = upstream::SIG_SIZE;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct PublicKey(pub(crate) upstream::LeanXmssPublicKey);

    impl PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self(upstream::LeanXmssPublicKey::from_bytes(&fixed(
                "leanXMSS public key",
                bytes,
            )?)))
        }

        pub fn to_bytes(&self) -> [u8; upstream::PUB_KEY_SIZE] {
            self.0.flatten()
        }
    }

    /// Holds every bottom tree it signed in last; regenerating it from its bytes costs a
    /// top-tree build.
    pub struct SecretKey {
        seed: upstream::Seed,
        inner: upstream::LeanXmssSecretKey,
    }

    impl std::fmt::Debug for SecretKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretKey")
                .field("public_key", &self.public_key())
                .finish_non_exhaustive()
        }
    }

    impl SecretKey {
        /// A fresh key from the operating system's randomness.
        pub fn generate() -> Self {
            Self::from_seed(leanvm::rand::random())
        }

        /// The seed is the key's entire secret material: never derive another key from it.
        pub fn from_seed(seed: upstream::Seed) -> Self {
            let (inner, _) = upstream::key_gen_from_seed(seed);
            Self { seed, inner }
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self::from_seed(fixed("leanXMSS secret key", bytes)?))
        }

        /// SECRET KEY MATERIAL: the seed.
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
            self.seed
        }

        pub fn public_key(&self) -> PublicKey {
            PublicKey(self.inner.public_key())
        }

        /// Builds the bottom tree `leaf_index` falls in ahead of signing there.
        pub fn prepare(&self, leaf_index: LeafIndex) -> Result<(), Error> {
            self.inner.prepare(leaf_index).map_err(Error::XmssSign)
        }

        /// Never sign two different messages at the same `leaf_index`.
        pub fn sign(&self, message: &Message, leaf_index: LeafIndex) -> Result<Signature, Error> {
            upstream::sign(&self.inner, message, leaf_index)
                .map(Signature)
                .map_err(Error::XmssSign)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Signature(pub(crate) upstream::LeanXmssSignature);

    impl Signature {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self(upstream::LeanXmssSignature::from_bytes(&fixed(
                "leanXMSS signature",
                bytes,
            )?)))
        }

        pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
            self.0.to_bytes()
        }

        /// The leaf index the signature was made at.
        pub fn leaf_index(&self) -> LeafIndex {
            self.0.leaf_index
        }
    }

    pub fn verify(
        public_key: &PublicKey,
        message: &Message,
        signature: &Signature,
    ) -> Result<(), Error> {
        upstream::verify(&public_key.0, message, &signature.0).map_err(Error::XmssVerify)
    }
}

/// leanSPHINCS: stateless, one tree of height 26. A key keeps one subtree of height
/// `kept_height`, trading signing capacity for key generation time.
pub mod sphincs {
    use super::{fixed, Error, Message};
    use leanvm::lean_sphincs as upstream;

    pub const SEED_LEN: usize = upstream::MASTER_SECRET_LEN;
    /// The seed, then the kept height.
    pub const SECRET_KEY_LEN: usize = upstream::SECRET_KEY_SIZE;
    pub const SIGNATURE_LEN: usize = upstream::SIG_SIZE;
    pub const MAX_KEPT_HEIGHT: usize = upstream::H;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct PublicKey(pub(crate) upstream::LeanSphincsPublicKey);

    impl PublicKey {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self(upstream::LeanSphincsPublicKey::from_bytes(&fixed(
                "leanSPHINCS public key",
                bytes,
            )?)))
        }

        pub fn to_bytes(&self) -> [u8; upstream::PUB_KEY_SIZE] {
            self.0.flatten()
        }
    }

    pub struct SecretKey(upstream::LeanSphincsSecretKey);

    impl std::fmt::Debug for SecretKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecretKey")
                .field("public_key", &self.public_key())
                .field("kept_height", &self.kept_height())
                .finish_non_exhaustive()
        }
    }

    impl SecretKey {
        /// A fresh key from the operating system's randomness.
        pub fn generate(kept_height: usize) -> Result<Self, Error> {
            Self::from_seed(leanvm::rand::random(), kept_height)
        }

        pub fn from_seed(seed: upstream::MasterSecret, kept_height: usize) -> Result<Self, Error> {
            if kept_height > MAX_KEPT_HEIGHT {
                return Err(Error::InvalidKeptHeight(kept_height));
            }
            Ok(Self(upstream::key_gen_from_seed(seed, kept_height).0))
        }

        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            let bytes = fixed::<SECRET_KEY_LEN>("leanSPHINCS secret key", bytes)?;
            upstream::LeanSphincsSecretKey::from_bytes(&bytes)
                .map(Self)
                .ok_or(Error::InvalidKeptHeight(usize::from(bytes[SEED_LEN])))
        }

        /// SECRET KEY MATERIAL: the seed, then the kept height.
        pub fn to_bytes(&self) -> [u8; SECRET_KEY_LEN] {
            self.0.to_bytes()
        }

        pub fn public_key(&self) -> PublicKey {
            PublicKey(self.0.public_key())
        }

        pub fn kept_height(&self) -> usize {
            self.0.kept_height()
        }

        pub fn sign(&self, message: &Message) -> Result<Signature, Error> {
            upstream::sign(&self.0, message)
                .map(Signature)
                .map_err(Error::SphincsSign)
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Signature(pub(crate) upstream::LeanSphincsSignature);

    impl Signature {
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Ok(Self(upstream::LeanSphincsSignature::from_bytes(&fixed(
                "leanSPHINCS signature",
                bytes,
            )?)))
        }

        pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
            self.0.to_bytes()
        }
    }

    pub fn verify(
        public_key: &PublicKey,
        message: &Message,
        signature: &Signature,
    ) -> Result<(), Error> {
        upstream::verify(&public_key.0, message, &signature.0).map_err(Error::SphincsVerify)
    }
}

/// A recursive proof that each listed public key signed its message. Every value of this
/// type has been proven by [`aggregate`] or verified by [`Aggregate::from_bytes`].
///
/// The proof attests the claims it lists, not the claims a caller wanted: compare
/// [`Aggregate::xmss_claims`] and [`Aggregate::sphincs_claims`] against what you expect.
#[derive(Clone, Debug)]
pub struct Aggregate(EthereumProof);

impl Aggregate {
    /// Decodes and verifies an aggregate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        setup();
        let proof = EthereumProof::from_bytes(bytes).map_err(Error::InvalidAggregate)?;
        proof.verify().map_err(Error::InvalidAggregate)?;
        Ok(Self(proof))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// The leanXMSS `(public key, message)` claims, strictly sorted.
    pub fn xmss_claims(&self) -> Vec<(xmss::PublicKey, Message)> {
        self.0
            .xmss_signers()
            .iter()
            .map(|(key, message)| (xmss::PublicKey(*key), *message))
            .collect()
    }

    /// The leanSPHINCS `(public key, message)` claims, strictly sorted.
    pub fn sphincs_claims(&self) -> Vec<(sphincs::PublicKey, Message)> {
        self.0
            .lean_sphincs_signers()
            .iter()
            .map(|(key, message)| (sphincs::PublicKey(*key), *message))
            .collect()
    }
}

/// Proves every raw signature and every child's claims in one aggregate whose claims are
/// their union. Raw signatures are verified first; at most [`MAX_CHILDREN`] children.
pub fn aggregate(
    children: &[&Aggregate],
    xmss: &[(xmss::PublicKey, Message, xmss::Signature)],
    sphincs: &[(sphincs::PublicKey, Message, sphincs::Signature)],
) -> Result<Aggregate, Error> {
    for (index, (key, message, signature)) in xmss.iter().enumerate() {
        xmss::verify(key, message, signature).map_err(|_| Error::InvalidXmssSignature { index })?;
    }
    for (index, (key, message, signature)) in sphincs.iter().enumerate() {
        sphincs::verify(key, message, signature)
            .map_err(|_| Error::InvalidSphincsSignature { index })?;
    }
    let children: Vec<EthereumProof> = children.iter().map(|child| child.0.clone()).collect();
    let xmss = xmss
        .iter()
        .map(|(key, message, signature)| (key.0, *message, signature.0.clone()))
        .collect();
    let sphincs = sphincs
        .iter()
        .map(|(key, message, signature)| (key.0, *message, signature.0.clone()))
        .collect();
    setup();
    let _prover = PROVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    leanvm::aggregate(&children, xmss, sphincs, &[], None, LOG_INV_RATE)
        .map(Aggregate)
        .map_err(Error::Aggregation)
}

/// The most children one [`aggregate`] call accepts.
pub const MAX_CHILDREN: usize = leanvm::MAX_RECURSIONS;
