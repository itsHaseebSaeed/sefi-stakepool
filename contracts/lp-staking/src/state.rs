use cosmwasm_std::{HumanAddr, CanonicalAddr, Uint128, Storage, Env, StdResult, StdError};
use scrt_finance::types::SecretContract;
use serde::{Deserialize, Serialize};
use cosmwasm_storage::{Singleton, ReadonlySingleton, singleton_read,singleton};
pub static LOTTERY_KEY: &[u8] = b"lottery";
pub static LOG_KEY: &[u8] = b"log";


#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
pub struct Config {
    pub admin: HumanAddr,
    pub reward_token: SecretContract,
    pub inc_token: SecretContract,
    pub master: SecretContract,
    pub viewing_key: String,
    pub prng_seed: Vec<u8>,
    pub is_stopped: bool,
    pub own_addr: HumanAddr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Lottery {
    pub entries: Vec<(CanonicalAddr, Uint128)>,
    pub entropy: Vec<u8>,
    pub seed: Vec<u8>,
    pub duration: u64,
    pub start_height: u64,
    pub end_height: u64,
}



pub fn lottery<S: Storage>(storage: &mut S) -> Singleton<S, Lottery> {
    singleton(storage, LOTTERY_KEY)
}

pub fn lottery_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, Lottery> {
    singleton_read(storage, LOTTERY_KEY)
}

pub fn log_string<S: Storage>(storage: &mut S) -> Singleton<S, String> {
    singleton(storage, LOG_KEY)
}

pub fn log_read<S: Storage>(storage: &S) -> ReadonlySingleton<S, String> {
    singleton_read(storage, LOG_KEY)
}

