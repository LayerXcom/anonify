use crate::bincode;
use crate::local_anyhow::{anyhow, Error, Result};
use crate::localstd::{
    collections::BTreeMap,
    convert::TryFrom,
    fmt::Debug,
    mem::size_of,
    ops::{Add, Div, Mul, Sub},
    vec::Vec,
};
use crate::serde::{Deserialize, Serialize};
use crate::serde_bytes;
use frame_common::{
    crypto::AccountId,
    state_types::StateType,
    traits::{State, StateDecoder, StateVector},
};

macro_rules! impl_uint {
    ($name:ident, $raw:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            PartialEq,
            PartialOrd,
            Eq,
            Ord,
            Hash,
            Serialize,
            Deserialize,
        )]
        #[serde(crate = "crate::serde")]
        pub struct $name($raw);

        impl From<$name> for StateType {
            fn from(u: $name) -> Self {
                StateType::new(bincode::serialize(&u).unwrap()) // must not fail
            }
        }

        impl TryFrom<StateType> for $name {
            type Error = Error;

            fn try_from(s: StateType) -> Result<Self, Self::Error> {
                if s.len() == 0 {
                    return Ok(Default::default());
                }
                let buf = s.into_vec();
                $name::decode_s(&buf)
            }
        }

        impl Add for $name {
            type Output = $name;

            fn add(self, other: Self) -> Self {
                let r = self.0 + other.0;
                $name(r)
            }
        }

        impl Sub for $name {
            type Output = $name;

            fn sub(self, other: Self) -> Self {
                let r = self.0 - other.0;
                $name(r)
            }
        }

        impl Mul<$name> for $name {
            type Output = $name;

            fn mul(self, rhs: Self) -> Self {
                let r = self.0 * rhs.0;
                $name(r)
            }
        }

        impl Div<$name> for $name {
            type Output = $name;

            fn div(self, rhs: Self) -> Self {
                let r = self.0 / rhs.0;
                $name(r)
            }
        }

        impl StateVector for $name {}

        impl StateDecoder for $name {
            fn decode_vec(v: Vec<u8>) -> Result<Self, Error> {
                if v.is_empty() {
                    return Ok(Default::default());
                }
                let buf = v;
                $name::decode_s(&buf)
            }

            fn decode_mut_bytes(b: &mut [u8]) -> Result<Self, Error> {
                if b.is_empty() {
                    return Ok(Default::default());
                }
                $name::decode_s(b)
            }
        }

        impl $name {
            pub fn as_raw(&self) -> $raw {
                self.0
            }

            pub fn from_raw(u: $raw) -> Self {
                $name(u)
            }

            pub fn zero() -> Self {
                $name(0)
            }
        }
    };
}

impl_uint!(U16, u16);
impl_uint!(U32, u32);
impl_uint!(U64, u64);

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Bytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl From<Vec<u8>> for Bytes {
    fn from(v: Vec<u8>) -> Self {
        Bytes(v)
    }
}

impl Bytes {
    pub fn new(inner: Vec<u8>) -> Self {
        Bytes(inner)
    }

    pub fn size(&self) -> usize {
        self.0.len() * size_of::<u8>()
    }

    pub fn into_raw(self) -> Vec<u8> {
        self.0
    }
}

impl StateDecoder for Bytes {
    fn decode_vec(v: Vec<u8>) -> Result<Self, Error> {
        if v.is_empty() {
            return Ok(Default::default());
        }
        let buf = v;
        Bytes::decode_s(&buf)
    }

    fn decode_mut_bytes(b: &mut [u8]) -> Result<Self, Error> {
        if b.is_empty() {
            return Ok(Default::default());
        }
        Bytes::decode_s(b)
    }
}

impl From<Bytes> for StateType {
    fn from(bs: Bytes) -> Self {
        StateType::new(bs.0.encode_s())
    }
}

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Approved(BTreeMap<AccountId, U64>);

impl Approved {
    pub fn new(inner: BTreeMap<AccountId, U64>) -> Self {
        Approved(inner)
    }

    pub fn total(&self) -> U64 {
        self.0.iter().fold(U64(0), |acc, (_, &amount)| acc + amount)
    }

    pub fn get(&self, account_id: AccountId) -> U64 {
        self.0.get(&account_id).copied().unwrap_or_default()
    }

    pub fn approve(&mut self, account_id: AccountId, amount: U64) {
        match self.allowance(&account_id) {
            Some(&existing_amount) => {
                self.0.insert(account_id, existing_amount + amount);
            }
            None => {
                self.0.insert(account_id, amount);
            }
        }
    }

    pub fn consume(&mut self, account_id: AccountId, amount: U64) -> Result<(), Error> {
        match self.allowance(&account_id) {
            Some(&existing_amount) => {
                if existing_amount < amount {
                    return Err(anyhow!(
                        "{:?} doesn't have enough balance to consume {:?}.",
                        account_id,
                        amount,
                    ));
                }
                self.0.insert(account_id, existing_amount - amount);
                Ok(())
            }
            None => Err(anyhow!("{:?} doesn't have any balance.", account_id)),
        }
    }

    pub fn allowance(&self, account_id: &AccountId) -> Option<&U64> {
        self.0.get(account_id)
    }

    pub fn size(&self) -> usize {
        self.0.len() * (AccountId::default().size() + U64::default().size())
    }
}

impl From<Approved> for StateType {
    fn from(a: Approved) -> Self {
        StateType::new(a.0.encode_s())
    }
}

impl StateDecoder for Approved {
    fn decode_vec(v: Vec<u8>) -> Result<Self, Error> {
        if v.is_empty() {
            return Ok(Default::default());
        }
        let buf = v;
        Approved::decode_s(&buf)
    }

    fn decode_mut_bytes(b: &mut [u8]) -> Result<Self, Error> {
        if b.is_empty() {
            return Ok(Default::default());
        }
        Approved::decode_s(b)
    }
}

#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Eq, Ord, Hash, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct StateVec<S: StateVector>(Vec<S>);

pub struct StateVecIter<'a, S: StateVector> {
    a: &'a StateVec<S>,
    now: usize,
}

impl<S> StateVec<S>
where
    S: StateVector,
{
    pub fn new() -> Self {
        let v: Vec<S> = Vec::new();
        StateVec(v)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn push(&mut self, v: S) {
        self.0.push(v)
    }

    pub fn from(v: Vec<S>) -> Self {
        StateVec(v)
    }

    pub fn iter(&self) -> StateVecIter<S> {
        StateVecIter { a: &self, now: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a, T> Iterator for StateVecIter<'a, T>
where
    T: StateVector + Clone,
{
    type Item = T;
    fn next(&mut self) -> Option<T> {
        self.now += 1;
        if self.now - 1 < self.a.0.len() {
            Some(self.a.0[&self.now - 1].clone())
        } else {
            None
        }
    }
}

impl<S: StateVector> StateVector for StateVec<S> {}

impl<T> From<StateVec<T>> for StateType
where
    T: StateVector + State,
{
    fn from(a: StateVec<T>) -> Self {
        StateType::new(a.0.encode_s())
    }
}

impl<T> StateDecoder for StateVec<T>
where
    T: StateVector + State,
{
    fn decode_vec(v: Vec<u8>) -> Result<Self, Error> {
        if v.is_empty() {
            return Ok(Default::default());
        }
        let buf = v;
        StateVec::decode_s(&buf)
    }

    fn decode_mut_bytes(b: &mut [u8]) -> Result<Self, Error> {
        if b.is_empty() {
            return Ok(Default::default());
        }
        StateVec::decode_s(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_encode() {
        let mut v = U64(10).encode_s();
        assert_eq!(U64(10), U64::decode_s(&mut v).unwrap());
    }

    #[test]
    fn test_from_state() {
        assert_eq!(U64(100), U64::from_state(&U64(100)).unwrap());
    }

    #[test]
    fn test_size() {
        assert_eq!(U16(0).size(), 2);
        assert_eq!(U32(0).size(), 4);
        assert_eq!(U64(0).size(), 8);
    }
}
