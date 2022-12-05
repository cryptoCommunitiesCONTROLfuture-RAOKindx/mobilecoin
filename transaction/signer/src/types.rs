//! Serializable types for sync between full-service and offline / hardware wallet implementations.

use serde::{Serialize, Deserialize};
use mc_core::{
    keys::{TxOutPublic, RootSpendPublic, RootViewPrivate},
    account_id::AccountId,
};
use mc_crypto_ring_signature::{KeyImage};
use mc_transaction_core::{tx::{Tx, TxPrefix}, ring_ct::{InputRing, OutputSecret}, BlockVersion};


/// View account credentials for sync with full-service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Root view private key
    #[serde(with = "pri_key_hex")]
    pub view_private: RootViewPrivate,

    /// Root spend public key
    #[serde(with = "pub_key_hex")]
    pub spend_public: RootSpendPublic,

    /// SLIP-0010 account index used for key derivation
    pub account_index: u32,
}

/// Convert a serializable signer [ViewAccount] object to the `mc_core` version
impl From<AccountInfo> for mc_core::account::ViewAccount {
    fn from(v: AccountInfo) -> Self {
        mc_core::account::ViewAccount::new(v.view_private, v.spend_public)
    }
}

/// Request to sync TxOuts for the provided account
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSyncReq {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// SLIP-0010 account index for wallet derivation (currently easier as a command line arg)
    #[cfg(nyet)]
    pub account_index: u32,

    /// TxOut subaddress and public key pairs to be synced
    pub txos: Vec<TxoUnsynced>,
}


/// Unsynced TxOut subaddress and public key pair for resolving key images
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoUnsynced {
    /// Subaddress for unsynced TxOut
    #[serde(with = "u64_hex")]
    pub subaddress: u64,

    /// tx_out_public_key for unsynced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_out_public_key: TxOutPublic,
}

/// Synced TxOut response, returned to full-service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSyncResp {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// public keys and key images for synced TxOuts
    pub txos: Vec<TxoSynced>,
}

/// Synced TxOut instance, contains public key and resolved key image for owned TxOuts
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSynced {
    /// tx_out_public_key for synced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_out_public_key: TxOutPublic,

    /// recovered key image for synced TxOut
    #[serde(with = "const_array_hex")]
    pub key_image: KeyImage,
}


/// Transaction signing request from full-service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxSignReq {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// SLIP-0010 account index for wallet derivation (currently easier as a command line arg)
    #[cfg(nyet)]
    pub account_index: u32,

    /// The fully constructed TxPrefix.
    pub tx_prefix: TxPrefix,

    /// rings
    pub rings: Vec<InputRing>,

    /// Output secrets
    pub output_secrets: Vec<OutputSecret>,

    /// Block version
    pub block_version: BlockVersion,
}

/// Transaction signing response, returned to full service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxSignResp {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// Signed transaction
    pub tx: Tx,
}


/// Public key hex encoding support for serde
pub mod pub_key_hex {
    use mc_core::keys::Key;
    use mc_crypto_keys::{RistrettoPublic};
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;


    pub fn serialize<S, ADDR, KIND>(t: &Key<ADDR, KIND, RistrettoPublic>, serializer: S) -> Result<S::Ok, S::Error> 
    where 
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(deserializer: D) -> Result<Key<ADDR, KIND, RistrettoPublic>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32>{})?;

        Key::try_from(&b)
            .map_err(|_e| <D as Deserializer<'de>>::Error::custom("failed to parse ristretto public key"))
    }
}

/// Private key hex encoding support for serde
pub mod pri_key_hex {
    use mc_core::keys::Key;
    use mc_crypto_keys::{RistrettoPrivate};
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;


    pub fn serialize<S, ADDR, KIND>(t: &Key<ADDR, KIND, RistrettoPrivate>, serializer: S) -> Result<S::Ok, S::Error> 
    where 
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(deserializer: D) -> Result<Key<ADDR, KIND, RistrettoPrivate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32>{})?;

        Key::try_from(&b)
            .map_err(|_e| <D as Deserializer<'de>>::Error::custom("failed to parse ristretto private key"))
    }
}

/// Constant array based type hex encoding for serde (use via `#[serde(with = "const_array_hex")]`)
pub mod const_array_hex {
    use serde::de::{Deserializer, Error};
    use super::ConstArrayVisitor;

    pub fn serialize<S: serde::ser::Serializer, const N: usize>(t: impl AsRef<[u8; N]>, serializer: S) -> Result<S::Ok, S::Error> {
        let s = hex::encode(t.as_ref());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, 'a, D, T, const N: usize>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::de::Deserializer<'de>,
        T: TryFrom<[u8; N]>,
        <T as TryFrom<[u8; N]>>::Error: core::fmt::Display,
    {
        let v = deserializer.deserialize_str(ConstArrayVisitor::<N>{})?;

        T::try_from(v)
            .map_err(|e| <D as Deserializer>::Error::custom(e))
    }
}


/// u64 hex encoding for serde (use via `#[serde(with = "u64_hex")]`)
pub mod u64_hex {
    use super::ConstArrayVisitor;

    pub fn serialize<S: serde::ser::Serializer>(t: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        let b = t.to_le_bytes();
        let s = hex::encode(b.as_ref());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, 'a, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let v = deserializer.deserialize_str(ConstArrayVisitor::<8>{})?;

        Ok(u64::from_le_bytes(v))
    }
}
/// Serde visitor for hex encoded fixed length byte arrays
pub(crate) struct ConstArrayVisitor<const N: usize = 32>;

/// Serde visitor implementation for fixed length arrays of hex-encoded bytes
impl<'de, const N: usize> serde::de::Visitor<'de> for ConstArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(
            formatter,
            concat!("A hex encoded array of bytes")
        )
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        let mut b = [0u8; N];

        hex::decode_to_slice(s, &mut b)
            .map_err(|e| E::custom(e))?;

        Ok(b)
    }
}


/// Serde visitor for hex encoded variable length byte arrays
pub(crate) struct VarArrayVisitor;

/// Serde visitor implementation for variable length arrays of hex-encoded protobufs
impl<'de> serde::de::Visitor<'de> for VarArrayVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(
            formatter,
            concat!("A hex encoded array of bytes")
        )
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        let b = hex::decode(s)
            .map_err(|e| E::custom(e))?;

        Ok(b)
    }
}
