// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Initiator-specific transition functions

use std::time::SystemTime;

use crate::{
    AuthPending, AuthRequestOutput, AuthResponseInput, ClientInitiate, Error, NodeInitiate, Ready,
    Start, Terminated, Transition, UnverifiedReport,
};
use alloc::vec::Vec;
use der::DateTime;
use mc_attest_core::{DcapEvidence, EvidenceKind, EvidenceMessage, ReportDataMask, VerificationReport};
use mc_attest_verifier::{DcapVerifier, Verifier, DEBUG_ENCLAVE};
use mc_attestation_verifier::Evidence;
use mc_crypto_keys::{Kex, ReprBytes};
use mc_crypto_noise::{
    HandshakeIX, HandshakeNX, HandshakeOutput, HandshakePattern, HandshakeState, HandshakeStatus,
    NoiseCipher, NoiseDigest, ProtocolName,
};
use prost::Message;
use rand_core::{CryptoRng, RngCore};

/// Helper function to create the output for an initiate
fn parse_handshake_output<Handshake, KexAlgo, Cipher, DigestAlgo>(
    output: HandshakeOutput<KexAlgo, Cipher, DigestAlgo>,
) -> Result<
    (
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<Handshake, KexAlgo, Cipher, DigestAlgo>,
    ),
    Error,
>
where
    Handshake: HandshakePattern,
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    match output.status {
        HandshakeStatus::InProgress(state) => Ok((
            AuthPending::new(state),
            AuthRequestOutput::<Handshake, KexAlgo, Cipher, DigestAlgo>::from(output.payload),
        )),
        HandshakeStatus::Complete(_output) => Err(Error::EarlyHandshakeComplete),
    }
}

/// Start + ClientInitiate => AuthPending + AuthRequestOutput
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        ClientInitiate<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestAlgo>,
    > for Start
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
    ProtocolName<HandshakeNX, KexAlgo, Cipher, DigestAlgo>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        _input: ClientInitiate<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestAlgo>,
            AuthRequestOutput<HandshakeNX, KexAlgo, Cipher, DigestAlgo>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeNX, KexAlgo, Cipher, DigestAlgo>::default(),
            self.responder_id.as_ref(),
            None,
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &[])
                .map_err(Error::HandshakeWrite)?,
        )
    }
}

/// Start + NodeInitiate => AuthPending + AuthRequestOutput
impl<KexAlgo, Cipher, DigestAlgo>
    Transition<
        AuthPending<KexAlgo, Cipher, DigestAlgo>,
        NodeInitiate<KexAlgo, Cipher, DigestAlgo>,
        AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestAlgo>,
    > for Start
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
    ProtocolName<HandshakeIX, KexAlgo, Cipher, DigestAlgo>: AsRef<str>,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        csprng: &mut R,
        input: NodeInitiate<KexAlgo, Cipher, DigestAlgo>,
    ) -> Result<
        (
            AuthPending<KexAlgo, Cipher, DigestAlgo>,
            AuthRequestOutput<HandshakeIX, KexAlgo, Cipher, DigestAlgo>,
        ),
        Self::Error,
    > {
        let handshake_state = HandshakeState::new(
            true,
            ProtocolName::<HandshakeIX, KexAlgo, Cipher, DigestAlgo>::default(),
            self.responder_id.as_ref(),
            Some(input.local_identity),
            None,
            None,
            None,
        )
        .map_err(Error::HandshakeInit)?;

        let mut serialized_report = Vec::with_capacity(input.ias_report.encoded_len());
        input
            .ias_report
            .encode(&mut serialized_report)
            .expect("Invariants failure, encoded_len insufficient to encode IAS report");

        parse_handshake_output(
            handshake_state
                .write_message(csprng, &serialized_report)
                .map_err(Error::HandshakeWrite)?,
        )
    }
}

/// AuthPending + AuthResponseInput => Ready + EvidenceMessage
impl<KexAlgo, Cipher, DigestAlgo> Transition<Ready<Cipher>, AuthResponseInput, EvidenceMessage>
    for AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: AuthResponseInput,
    ) -> Result<(Ready<Cipher>, EvidenceMessage), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(result) => {
                // Received EvidenceMessage
                if let Ok(remote_evidence) = EvidenceMessage::decode(output.payload.as_slice()) {
                    match remote_evidence.evidence {
                        Some(evidence_kind) => {
                            match evidence_kind {
                                EvidenceKind::Dcap(dcap_evidence) => {
                                    let (quote, collateral, report_data) = match dcap_evidence {
                                        DcapEvidence {
                                            quote: Some(quote),
                                            collateral: Some(collateral),
                                            report_data: Some(report_data)
                                        } => (quote, collateral, report_data),
                                        _ => return Err(Error::EvidenceDeserialization),
                                    };

                                    let verifier = DcapVerifier::new(
                                        input.identities,
                                        DateTime::from(SystemTime),
                                        report_data,
                                    );
                                    let evidence = Evidence::new(quote, collateral)
                                        .map_err(|e| Error::EvidenceDeserialization)?;
                                    match verifier.verify(evidence).is_success().unwrap_u8() {
                                        1 => {
                                            Ok((
                                                Ready {
                                                    writer: result.initiator_cipher,
                                                    reader: result.responder_cipher,
                                                    binding: result.channel_binding,
                                                },
                                                EvidenceMessage {
                                                    evidence: Some(EvidenceKind::Dcap(dcap_evidence))
                                                },
                                            ))
                                        },
                                        _ => Err(Error::EvidenceVerification),
                                    }
                                    
                                },
                                // We shouldn't be getting anything other than Dcap here
                                _ => Err(Error::EvidenceDeserialization),
                            }
                        }
                        None => Err(Error::EvidenceDeserialization)
                    }
                }
                // Received IAS report
                else {
                    let remote_report = VerificationReport::decode(output.payload.as_slice())
                        .map_err(|_e| Error::ReportDeserialization)?;

                    let identities = input.identities;
                    let mut verifier = Verifier::default();
                    verifier.identities(&identities).debug(DEBUG_ENCLAVE);

                    // We are not returning the report data and instead returning the raw report
                    // since that also includes the signature and certificate chain.
                    // However, we still make sure the report contains valid data
                    // before we continue by calling `.verify`. Callers can then
                    // safely construct a VerificationReportData object out of the
                    // VerificationReport returned.
                    let _report_data = verifier
                        .report_data(
                            &result
                                .remote_identity
                                .ok_or(Error::MissingRemoteIdentity)?
                                .map_bytes(|bytes| {
                                    ReportDataMask::try_from(bytes)
                                        .map_err(|_| Error::BadRemoteIdentity)
                                })?,
                        )
                        .verify(&remote_report)?;
                    Ok((
                        Ready {
                            writer: result.initiator_cipher,
                            reader: result.responder_cipher,
                            binding: result.channel_binding,
                        },
                        EvidenceMessage {
                            evidence: Some(EvidenceKind::Epid(remote_report))
                        },
                    ))
                }
            }
        }
    }
}

/// AuthPending + UnverifiedReport => Terminated + EvidenceMessage
impl<KexAlgo, Cipher, DigestAlgo> Transition<Terminated, UnverifiedReport, EvidenceMessage>
    for AuthPending<KexAlgo, Cipher, DigestAlgo>
where
    KexAlgo: Kex,
    Cipher: NoiseCipher,
    DigestAlgo: NoiseDigest,
{
    type Error = Error;

    fn try_next<R: CryptoRng + RngCore>(
        self,
        _csprng: &mut R,
        input: UnverifiedReport,
    ) -> Result<(Terminated, EvidenceMessage), Self::Error> {
        let output = self
            .state
            .read_message(input.as_ref())
            .map_err(Error::HandshakeRead)?;
        match output.status {
            HandshakeStatus::InProgress(_state) => Err(Error::HandshakeNotComplete),
            HandshakeStatus::Complete(_) => {
                if let Ok(remote_evidence) = EvidenceMessage::decode(output.payload.as_slice()) {
                    match remote_evidence.evidence {
                        Some(EvidenceKind::Dcap(dcap_evidence)) => Ok((Terminated, EvidenceMessage { evidence: Some(EvidenceKind::Dcap(dcap_evidence)) })),
                        _ => Err(Error::ReportDeserialization),
                    }
                }
                else {
                    let remote_report = VerificationReport::decode(output.payload.as_slice())
                        .map_err(|_| Error::ReportDeserialization)?;

                    Ok((Terminated, EvidenceMessage { evidence: Some(EvidenceKind::Epid(remote_report)) }))
                }
            }
        }
    }
}
