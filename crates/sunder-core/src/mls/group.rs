//! Client-side MLS group state machine.

use std::time::Instant;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use sunder_proto::Frame;

use super::{error::MlsError, provider::SunderMlsProvider};
use crate::env::Environment;

/// Room identifier (128-bit UUID).
pub type RoomId = u128;

/// Member identifier within a group.
pub type MemberId = u64;

/// Actions that MLS group operations can produce.
///
/// The application layer is responsible for executing these actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsAction {
    /// Send proposal frame to sequencer
    SendProposal(Frame),

    /// Send commit frame to sequencer
    SendCommit(Frame),

    /// Send welcome message to new member
    SendWelcome {
        /// Member ID to send welcome message to
        recipient: MemberId,
        /// Welcome frame containing group secrets
        frame: Frame,
    },

    /// Send application message to group (via sequencer)
    SendMessage(Frame),

    /// Deliver decrypted application message to application
    DeliverMessage {
        /// Member ID who sent the message
        sender: MemberId,
        /// Decrypted message plaintext
        plaintext: Vec<u8>,
    },

    /// Remove this group (we were kicked/banned or left)
    RemoveGroup {
        /// Reason for removal
        reason: String,
    },

    /// Log event for debugging/monitoring
    Log {
        /// Log message
        message: String,
    },
}

/// Client-side MLS group state.
///
/// Represents participation in a single MLS group (room). Clients can be
/// members of multiple groups simultaneously.
///
/// # Invariants
///
/// - Epoch only increases (never decreases)
/// - All members at same epoch have identical tree hash
/// - Only members can encrypt/decrypt messages for current epoch
///
/// # Type Parameters
///
/// - `E`: The environment implementation (SimEnv or SystemEnv)
pub struct MlsGroup<E: Environment> {
    /// Room identifier
    room_id: RoomId,

    /// Our member ID in this group
    member_id: MemberId,

    /// OpenMLS group instance (contains all MLS state)
    mls_group: openmls::group::MlsGroup,

    /// Our signature keypair for this group
    signer: SignatureKeyPair,

    /// Provider for crypto/storage/RNG
    provider: SunderMlsProvider<E>,

    /// Pending commit that we sent (waiting for sequencer acceptance)
    pending_commit: Option<PendingCommit>,
}

/// Tracks a commit we sent that's waiting for sequencer acceptance.
#[derive(Debug, Clone)]
struct PendingCommit {
    /// Epoch this commit will create
    #[allow(dead_code)] // Will be used when we implement commit handling
    target_epoch: u64,

    /// When we sent it (for timeout detection)
    sent_at: Instant,
}

impl<E: Environment> MlsGroup<E> {
    /// Create a new MLS group.
    ///
    /// This initializes a new group at epoch 0. The creator becomes the first
    /// member and can add other members via proposals + commits.
    ///
    /// # Arguments
    ///
    /// * `env` - Environment for RNG and time
    /// * `room_id` - Unique identifier for this room
    /// * `member_id` - Our member ID in this group
    /// * `_now` - Current time (reserved for future use)
    ///
    /// # Returns
    ///
    /// Returns a tuple containing a new `MlsGroup` instance and any actions to
    /// execute.
    ///
    /// # Errors
    ///
    /// Returns an error if MLS group creation fails (crypto initialization,
    /// etc.)
    pub fn new(
        env: E,
        room_id: RoomId,
        member_id: MemberId,
        _now: Instant,
    ) -> Result<(Self, Vec<MlsAction>), MlsError> {
        // Create the provider with our environment
        let provider = SunderMlsProvider::new(env);

        // Use a standard ciphersuite (Curve25519 + AES-128-GCM + SHA256 + Ed25519)
        let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        // Generate signature keypair
        let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm())
            .map_err(|e| MlsError::Crypto(format!("Failed to generate keypair: {}", e)))?;

        // Create credential with our member ID
        let credential = BasicCredential::new(member_id.to_le_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };

        // MLS group configuration
        let group_config = MlsGroupCreateConfig::builder().ciphersuite(ciphersuite).build();

        // Create the MLS group
        let mls_group =
            openmls::group::MlsGroup::new(&provider, &signer, &group_config, credential_with_key)
                .map_err(|e| MlsError::Crypto(format!("Failed to create MLS group: {}", e)))?;

        let group = Self { room_id, member_id, mls_group, signer, provider, pending_commit: None };

        let actions = vec![MlsAction::Log {
            message: format!("Created group {} at epoch 0 (member_id={})", room_id, member_id),
        }];

        Ok((group, actions))
    }

    /// Get the current epoch number.
    pub fn epoch(&self) -> u64 {
        self.mls_group.epoch().as_u64()
    }

    /// Get our member ID.
    pub fn member_id(&self) -> MemberId {
        self.member_id
    }

    /// Get the room ID.
    pub fn room_id(&self) -> RoomId {
        self.room_id
    }

    /// Get the MLS group ID.
    pub fn group_id(&self) -> &GroupId {
        self.mls_group.group_id()
    }

    /// Check if we have a pending commit waiting for acceptance.
    pub fn has_pending_commit(&self) -> bool {
        self.pending_commit.is_some()
    }

    /// Check if a pending commit has timed out.
    ///
    /// Returns true if we have a pending commit that's been waiting for at
    /// least the timeout duration (inclusive).
    pub fn is_commit_timeout(&self, now: Instant, timeout: std::time::Duration) -> bool {
        self.pending_commit
            .as_ref()
            .map(|pending| now.duration_since(pending.sent_at) >= timeout)
            .unwrap_or(false)
    }

    /// Process an incoming MLS Commit frame.
    ///
    /// This function processes a commit message, updates the group state,
    /// and returns any actions that need to be taken as a result.
    ///
    /// # Arguments
    ///
    /// * `_frame` - The commit frame to process
    ///
    /// # Returns
    ///
    /// Returns a vector of `MlsAction` that should be executed by the caller
    ///
    /// # Errors
    ///
    /// Returns an error if the commit is invalid or cannot be processed.
    pub fn process_commit(&mut self, _frame: Frame) -> Result<Vec<MlsAction>, MlsError> {
        // TODO: Implement actual MLS commit processing
        // This requires:
        // 1. Environment trait for RNG
        // 2. mls-rs integration with deterministic crypto
        // 3. Proper frame deserialization using sunder-proto payloads

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    // Test environment using system RNG (std::time::Instant)
    #[derive(Clone)]
    struct TestEnv;

    impl Environment for TestEnv {
        type Instant = Instant;

        fn now(&self) -> Self::Instant {
            Instant::now()
        }

        fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send {
            async move {
                tokio::time::sleep(duration).await;
            }
        }

        fn random_bytes(&self, buffer: &mut [u8]) {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(buffer);
        }
    }

    #[test]
    fn create_group() {
        let env = TestEnv;
        let now = Instant::now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (group, actions) =
            MlsGroup::new(env, room_id, member_id, now).expect("create should succeed");

        assert_eq!(group.room_id(), room_id);
        assert_eq!(group.member_id(), member_id);
        assert_eq!(group.epoch(), 0);
        assert!(!group.has_pending_commit());

        // Should have logged group creation
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], MlsAction::Log { .. }));
    }

    #[test]
    fn commit_timeout_detection() {
        let env = TestEnv;
        let now = Instant::now();
        let room_id = 0x1234_5678_9abc_def0_1234_5678_9abc_def0;
        let member_id = 1;

        let (mut group, _) = MlsGroup::new(env, room_id, member_id, now).unwrap();

        // No pending commit initially
        assert!(!group.is_commit_timeout(now, Duration::from_secs(5)));

        // Set a pending commit
        group.pending_commit = Some(PendingCommit { sent_at: now, target_epoch: 1 });

        // Not timed out yet
        assert!(!group.is_commit_timeout(now + Duration::from_secs(4), Duration::from_secs(5)));

        // Just at timeout
        assert!(group.is_commit_timeout(now + Duration::from_secs(5), Duration::from_secs(5)));

        // After timeout
        assert!(group.is_commit_timeout(now + Duration::from_secs(6), Duration::from_secs(5)));
    }
}
