// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Mocks the ConsensusEnclave for testing.

#![allow(clippy::ptr_arg)] // Clippy seems to complain about autogenerated mocking code.

use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::*;
use mc_blockchain_types::{Block, BlockContents, BlockSignature};
use mc_common::ResponderId;
use mc_consensus_enclave_api::{
    BlockchainConfig, ConsensusEnclave, FeePublicKey, FormBlockInputs, LocallyEncryptedTx,
    Result as ConsensusEnclaveResult, SealedBlockSigningKey, TxContext, WellFormedEncryptedTx,
    WellFormedTxContext,
};
use mc_crypto_keys::{Ed25519Public, X25519Public};
use mc_sgx_report_cache_api::{ReportableEnclave, Result as SgxReportResult};
use mc_transaction_core::{
    tx::{TxOutMembershipElement, TxOutMembershipProof},
    TokenId,
};

use mockall::*;

// ConsensusEnclave inherits from ReportableEnclave, so the traits have o be
// re-typed here. Splitting the traits apart might help because TxManager only
// uses a few of these functions.

mock! {
    pub ConsensusEnclave {} // This is used to generate a MockConsensusEnclave struct.
    impl ConsensusEnclave for ConsensusEnclave {
        fn enclave_init(
            &self,
            self_peer_id: &ResponderId,
            self_client_id: &ResponderId,
            sealed_key: &Option<SealedBlockSigningKey>,
            blockchain_config: BlockchainConfig,
        ) -> ConsensusEnclaveResult<(SealedBlockSigningKey, Vec<String>)>;

        fn get_minimum_fee(&self, token_id: &TokenId) -> ConsensusEnclaveResult<Option<u64>>;

        fn get_identity(&self) -> ConsensusEnclaveResult<X25519Public>;

        fn get_signer(&self) -> ConsensusEnclaveResult<Ed25519Public>;

        fn get_fee_recipient(&self) -> ConsensusEnclaveResult<FeePublicKey>;

        fn get_minting_trust_root(&self) -> ConsensusEnclaveResult<Ed25519Public>;

        fn client_accept(&self, req: ClientAuthRequest) -> ConsensusEnclaveResult<(ClientAuthResponse, ClientSession)>;

        fn client_close(&self, channel_id: ClientSession) -> ConsensusEnclaveResult<()>;

        fn client_discard_message(&self, msg: EnclaveMessage<ClientSession>) -> ConsensusEnclaveResult<()>;

        fn peer_init(&self, peer_id: &ResponderId) -> ConsensusEnclaveResult<PeerAuthRequest>;

        fn peer_accept(&self, req: PeerAuthRequest) -> ConsensusEnclaveResult<(PeerAuthResponse, PeerSession)>;

        fn peer_connect(&self, peer_id: &ResponderId, res: PeerAuthResponse) -> ConsensusEnclaveResult<(PeerSession, VerificationReport)>;

        fn peer_close(&self, channel_id: &PeerSession) -> ConsensusEnclaveResult<()>;

        fn client_tx_propose(&self, msg: EnclaveMessage<ClientSession>) -> ConsensusEnclaveResult<TxContext>;

        fn client_tx_propose_v2(&self, msg: EnclaveMessage<ClientSession>) -> ConsensusEnclaveResult<TxContext>;

        fn peer_tx_propose(&self, msg: EnclaveMessage<PeerSession>) -> ConsensusEnclaveResult<Vec<TxContext>>;

        fn tx_is_well_formed(
            &self,
            locally_encrypted_tx: LocallyEncryptedTx,
            block_index: u64,
            proofs: Vec<TxOutMembershipProof>,
        ) -> ConsensusEnclaveResult<(WellFormedEncryptedTx, WellFormedTxContext)>;

        fn txs_for_peer(
            &self,
            encrypted_txs: &[WellFormedEncryptedTx],
            aad: &[u8],
            peer: &PeerSession,
        ) -> ConsensusEnclaveResult<EnclaveMessage<PeerSession>>;

        fn form_block(
            &self,
            parent_block: &Block,
            inputs: FormBlockInputs,
            root_element: &TxOutMembershipElement,
        ) -> ConsensusEnclaveResult<(Block, BlockContents, BlockSignature)>;
    }

    impl ReportableEnclave for ConsensusEnclave {
        fn new_ereport(&self, qe_info: TargetInfo) -> SgxReportResult<(Report, QuoteNonce)>;

        fn verify_quote(&self, quote: Quote, qe_report: Report) -> SgxReportResult<IasNonce>;

        fn verify_ias_report(&self, ias_report: VerificationReport) -> SgxReportResult<()>;

        fn get_ias_report(&self) -> SgxReportResult<VerificationReport>;
    }
}

#[cfg(test)]
mod mock_consensus_enclave_tests {
    use super::MockConsensusEnclave;
    use mc_consensus_enclave_api::ConsensusEnclave;
    use mc_crypto_keys::X25519Public;

    #[test]
    // Calling methods on the mock should return the specified values.
    fn test_with_mock() {
        let key = [0x55u8; 32];
        let identity = X25519Public::try_from(&key as &[u8]).unwrap();

        let mut mock_consensus_enclave = MockConsensusEnclave::new();
        mock_consensus_enclave
            .expect_get_identity()
            .times(1)
            .return_const(Ok(identity.clone()));

        let res = mock_consensus_enclave.get_identity();
        assert_eq!(res, Ok(identity));
    }
}
