use cosmwasm_std::{
    debug_print, from_binary, to_binary, Api, Binary, CosmosMsg, Env, Extern, HandleResponse,
    HumanAddr, InitResponse, Querier, ReadonlyStorage, StdError, StdResult, Storage, Uint128,
    WasmMsg,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use secret_toolkit::crypto::sha_256;
use secret_toolkit::snip20;
use secret_toolkit::storage::{TypedStore, TypedStoreMut};
use secret_toolkit::utils::{pad_handle_result, pad_query_result};

use crate::constants::*;
use crate::querier::query_pending;
use crate::state::{Config, Lottery, lottery, log_string};
use scrt_finance::lp_staking_msg::LPStakingResponseStatus::Success;
use scrt_finance::lp_staking_msg::{
    LPStakingHandleAnswer, LPStakingHandleMsg, LPStakingHookMsg, LPStakingInitMsg,
    LPStakingQueryAnswer, LPStakingQueryMsg, LPStakingReceiveAnswer, LPStakingReceiveMsg,
};
use scrt_finance::master_msg::MasterHandleMsg;
use scrt_finance::types::{RewardPool, TokenInfo, UserInfo};
use scrt_finance::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

use sha2::{Digest, Sha256};

use rand::distributions::WeightedIndex;
use rand::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rust_decimal::prelude::ToPrimitive;


pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: LPStakingInitMsg,
) -> StdResult<InitResponse> {
    // Initialize state
    let prng_seed_hashed = sha_256(&msg.prng_seed.0);
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    config_store.store(
        CONFIG_KEY,
        &Config {
            admin: env.message.sender.clone(),
            reward_token: msg.reward_token.clone(),
            inc_token: msg.inc_token.clone(),
            master: msg.master,
            viewing_key: msg.viewing_key.clone(),
            prng_seed: prng_seed_hashed.to_vec(),
            is_stopped: false,
            own_addr: env.contract.address,
        },
    )?;

    TypedStoreMut::<RewardPool, S>::attach(&mut deps.storage).store(
        REWARD_POOL_KEY,
        &RewardPool {
            inc_token_supply: 0,
            total_rewards: 0
        },
    )?;

    TypedStoreMut::<TokenInfo, S>::attach(&mut deps.storage)
        .store(TOKEN_INFO_KEY, &msg.token_info)?;

    // Register sSCRT and incentivized token, set vks
    let messages = vec![
        snip20::register_receive_msg(
            env.contract_code_hash.clone(),
            None,
            1, // This is public data, no need to pad
            msg.reward_token.contract_hash.clone(),
            msg.reward_token.address.clone(),
        )?,
        snip20::register_receive_msg(
            env.contract_code_hash,
            None,
            1,
            msg.inc_token.contract_hash.clone(),
            msg.inc_token.address.clone(),
        )?,
        snip20::set_viewing_key_msg(
            msg.viewing_key.clone(),
            None,
            RESPONSE_BLOCK_SIZE, // This is private data, need to pad
            msg.reward_token.contract_hash,
            msg.reward_token.address,
        )?,
        snip20::set_viewing_key_msg(
            msg.viewing_key,
            None,
            RESPONSE_BLOCK_SIZE,
            msg.inc_token.contract_hash,
            msg.inc_token.address,
        )?,
    ];


    //lottery init
    let height = env.block.height;
    let duration = 10u64;
    //Create first lottery
    ///Why entropy and seed are the same here
    let a_lottery = Lottery {
        entries: Vec::default(),
        entropy: prng_seed_hashed.to_vec(),
        start_height: height + 1,
        end_height: height + duration + 1,
        seed: prng_seed_hashed.to_vec(),
        duration
    };

    // Save to state
    lottery(&mut deps.storage).save(&a_lottery)?;



    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: LPStakingHandleMsg,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    if config.is_stopped {
        return match msg {
            LPStakingHandleMsg::EmergencyRedeem {} => emergency_redeem(deps, env),
            LPStakingHandleMsg::ResumeContract {} => resume_contract(deps, env),
            _ => Err(StdError::generic_err(
                "this contract is stopped and this action is not allowed",
            )),
        };
    }

    let response = match msg {
        LPStakingHandleMsg::Redeem { amount } => redeem(deps, env, amount),
        LPStakingHandleMsg::Receive {
            from, amount, msg, ..
        } => receive(deps, env, from, amount.u128(), msg),
        LPStakingHandleMsg::CreateViewingKey { entropy, .. } => {
            create_viewing_key(deps, env, entropy)
        }
        LPStakingHandleMsg::SetViewingKey { key, .. } => set_viewing_key(deps, env, key),
        LPStakingHandleMsg::StopContract {} => stop_contract(deps, env),
        LPStakingHandleMsg::ChangeAdmin { address } => change_admin(deps, env, address),
        LPStakingHandleMsg::NotifyAllocation { amount: rewards, hook } => notify_allocation(
            deps,
            env,
            rewards.u128(),
            hook.map(|h| from_binary(&h).unwrap()),
        ),
        LPStakingHandleMsg::ClaimRewards { } => claim_rewards(deps,env),
        _ => Err(StdError::generic_err("Unavailable or unknown action")),
    };

    pad_handle_result(response, RESPONSE_BLOCK_SIZE)
}

pub fn query<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: LPStakingQueryMsg,
) -> StdResult<Binary> {
    let response = match msg {
        LPStakingQueryMsg::ContractStatus {} => query_contract_status(deps),
        LPStakingQueryMsg::RewardToken {} => query_reward_token(deps),
        LPStakingQueryMsg::IncentivizedToken {} => query_incentivized_token(deps),
        LPStakingQueryMsg::TokenInfo {} => query_token_info(deps),
        _ => authenticated_queries(deps, msg),
    };

    pad_query_result(response, RESPONSE_BLOCK_SIZE)
}

pub fn authenticated_queries<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    msg: LPStakingQueryMsg,
) -> StdResult<Binary> {
    let (address, key) = msg.get_validation_params();

    let vk_store = ReadonlyPrefixedStorage::new(VIEWING_KEY_KEY, &deps.storage);
    let expected_key = vk_store.get(address.0.as_bytes());

    if expected_key.is_none() {
        // Checking the key will take significant time. We don't want to exit immediately if it isn't set
        // in a way which will allow to time the command and determine if a viewing key doesn't exist
        key.check_viewing_key(&[0u8; VIEWING_KEY_SIZE]);
    } else if key.check_viewing_key(expected_key.unwrap().as_slice()) {
        return match msg {
            LPStakingQueryMsg::Rewards {
                address, height, ..
            } => query_pending_rewards(deps, &address, height),
            LPStakingQueryMsg::Balance { address, .. } => query_deposit(deps, &address),
            _ => panic!("This should never happen"),
        };
    }

    Ok(to_binary(&LPStakingQueryAnswer::QueryError {
        msg: "Wrong viewing key for this address or viewing key not set".to_string(),
    })?)
}

// Handle functions
fn claim_rewards<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let config = TypedStore::<Config, S>::attach(&deps.storage).load(CONFIG_KEY)?;
    update_allocation(env, config , Some(to_binary(&LPStakingHookMsg::ClaimRewards {})?))
}




fn claim_rewards_hook<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    mut reward_pool:RewardPool,
) -> StdResult<HandleResponse> {
    let winning_amount = reward_pool.total_rewards;
    if winning_amount == 0 {
        return Err(StdError::generic_err(
            "no rewards available",
        ));
    }

    let mut a_lottery = lottery(&mut deps.storage).load()?;
    validate_end_height(a_lottery.end_height, env.block.height)?;
    validate_start_height(a_lottery.start_height, env.block.height)?;
    a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    a_lottery.entropy.extend(&env.block.time.to_be_bytes());

    // restart the lottery in the next block
    a_lottery.start_height = &env.block.height + 1;
    a_lottery.end_height = &env.block.height + a_lottery.duration + 1;
    lottery(&mut deps.storage).save(&a_lottery)?;

    let entries: Vec<_> = (&a_lottery.entries).into_iter().map(|(k, _,_)| k).collect();
    let weights:Vec<u128>= (&a_lottery.entries).into_iter().map(|(_, v,l)|
    if ((a_lottery.end_height-l)/a_lottery.duration) > 1 {
        v.u128()
    } else{
            v.u128()*((a_lottery.end_height-l)/a_lottery.duration).to_u128().unwrap()
        }
    ).collect();


    // log_string(&mut deps.storage).save(&format!("Number of entries = {}", &weights.len()))?;

    let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    let prng_seed = config.prng_seed;

    let mut hasher = Sha256::new();
    hasher.update(&prng_seed);
    hasher.update(&a_lottery.entropy);
    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_slice());

    let mut rng: ChaChaRng = ChaChaRng::from_seed(result);
    let dist = WeightedIndex::new(&weights).unwrap();
    let sample = dist.sample(&mut rng).clone();
    let winner = entries[sample];

    let winner_human = deps.api.human_address(&winner).unwrap();
    log_string(&mut deps.storage).save(&format!("And the winner is {}", winner_human.as_str()))?;

    let mut messages: Vec<CosmosMsg> = vec![];
    messages.push(secret_toolkit::snip20::transfer_msg(
        winner_human,
        Uint128(winning_amount),
        None,
        RESPONSE_BLOCK_SIZE,
        config.reward_token.contract_hash,
        config.reward_token.address,
    )?);

    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    reward_pool.total_rewards=0;
    rewards_store.store(REWARD_POOL_KEY, &reward_pool)?;



    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::ClaimRewardPool {
            status: Success,
        })?),
    })
}


fn receive<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
    msg: Binary,
) -> StdResult<HandleResponse> {
    let msg: LPStakingReceiveMsg = from_binary(&msg)?;

    match msg {
        LPStakingReceiveMsg::Deposit {} => deposit(deps, env, from, amount),
    }
}

fn notify_allocation<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    rewards: u128,
    hook: Option<LPStakingHookMsg>,
) -> StdResult<HandleResponse> {
    let config = TypedStore::<Config, S>::attach(&deps.storage).load(CONFIG_KEY)?;
    if env.message.sender != config.master.address && env.message.sender != config.admin {
        return Err(StdError::generic_err(
            "you are not allowed to call this function",
        ));
    }
    //amount == rewards
    let mut reward_pool = update_rewards(deps, /*&env, &config,*/ rewards)?;

    let mut response = Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: None,
    });

    if let Some(hook_msg) = hook {
        response = match hook_msg {
            LPStakingHookMsg::ClaimRewards { } => {
                claim_rewards_hook(deps, env,reward_pool)
            },
            _ => Err(StdError::generic_err(format!(
                "This hook message is not supported.")))
        }
    }

    response
}

fn deposit<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
) -> StdResult<HandleResponse> {
    // Ensure that the sent tokens are from an expected contract address
    let config = TypedStore::<Config, S>::attach(&deps.storage).load(CONFIG_KEY)?;
    if env.message.sender != config.inc_token.address {
        return Err(StdError::generic_err(format!(
            "This token is not supported. Supported: {}, given: {}",
            config.inc_token.address, env.message.sender
        )));
    }
    deposit_hook(deps,env,from,amount)
}

fn deposit_hook<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    from: HumanAddr,
    amount: u128,
) -> StdResult<HandleResponse> {
    let sender_address = deps.api.canonical_address(&from)?;
    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(from.0.as_bytes())
        .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: env.block.height }); // NotFound is the only possible error

    let account_balance = user.locked;

    let mut a_lottery = lottery(&mut deps.storage).load()?;
    if a_lottery.entries.len() > 0 {
        &a_lottery.entries.retain(|(k, _,_)| k != &sender_address);
    }

    user.start_height=env.block.height;

    &a_lottery.entries.push((
        sender_address,
        Uint128::from(account_balance + amount),
        user.start_height,
    ));
    &a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    lottery(&mut deps.storage).save(&a_lottery);

    user.locked+=amount;
    TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(from.0.as_bytes(), &user)?;
    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
    reward_pool.inc_token_supply+=amount;
    TypedStoreMut::attach(&mut deps.storage).store(REWARD_POOL_KEY, &reward_pool)?;

    Ok(HandleResponse {
        messages:vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingReceiveAnswer::Deposit {
            status: Success,
        })?),
    })
}

fn redeem<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    amount: Option<Uint128>,
) -> StdResult<HandleResponse> {
    let config = TypedStore::<Config, S>::attach(&deps.storage).load(CONFIG_KEY)?;
    redeem_hook(deps,env.clone(),config,env.message.sender,amount)
}

fn redeem_hook<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: Config,
    to: HumanAddr,
    amount: Option<Uint128>,
) -> StdResult<HandleResponse> {
    let sender_address = deps.api.canonical_address(&to)?;
    let mut user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(to.0.as_bytes())
        .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: env.block.height }); // NotFound is the only possible error
    let amount = amount.unwrap_or(Uint128(user.locked)).u128();

    if amount > user.locked {
        return Err(StdError::generic_err(format!(
            "insufficient funds to redeem: balance={}, required={}",
            user.locked, amount,
        )));
    }

    let mut messages: Vec<CosmosMsg> = vec![];
    let account_balance = user.locked;
    let mut a_lottery = lottery(&mut deps.storage).load()?;
    if a_lottery.entries.len() > 0 {
        &a_lottery.entries.retain(|(k, _,_)| k != &sender_address);
    }
    &a_lottery.entries.push((
        sender_address.clone(),
        Uint128::from(account_balance - amount),
        user.start_height,
    ));
    //
    &a_lottery.entropy.extend(&env.block.height.to_be_bytes());
    &a_lottery.entropy.extend(&env.block.time.to_be_bytes());
    lottery(&mut deps.storage).save(&a_lottery);
    // Transfer redeemed tokens
    user.locked -= amount;
    TypedStoreMut::<UserInfo, S>::attach(&mut deps.storage).store(to.0.as_bytes(), &user)?;

    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
    reward_pool.inc_token_supply -= amount;
    TypedStoreMut::attach(&mut deps.storage).store(REWARD_POOL_KEY, &reward_pool)?;
    messages.push(secret_toolkit::snip20::transfer_msg(
        to,
        Uint128(amount),
        None,
        RESPONSE_BLOCK_SIZE,
        config.inc_token.contract_hash,
        config.inc_token.address,
    )?);
    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::Redeem {
            status: Success,
        })?),
    })
}

pub fn create_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    entropy: String,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY)?;
    let prng_seed = config.prng_seed;

    let key = ViewingKey::new(&env, &prng_seed, (&entropy).as_ref());

    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &key.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::CreateViewingKey { key })?),
    })
}

pub fn set_viewing_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    key: String,
) -> StdResult<HandleResponse> {
    let vk = ViewingKey(key);

    let mut vk_store = PrefixedStorage::new(VIEWING_KEY_KEY, &mut deps.storage);
    vk_store.set(env.message.sender.0.as_bytes(), &vk.to_hashed());

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::SetViewingKey {
            status: Success,
        })?),
    })
}

fn stop_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let mut config: Config = config_store.load(CONFIG_KEY)?;

    enforce_admin(config.clone(), env)?;

    config.is_stopped = true;
    config_store.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::StopContract {
            status: Success,
        })?),
    })
}

fn resume_contract<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let mut config: Config = config_store.load(CONFIG_KEY)?;

    enforce_admin(config.clone(), env)?;

    config.is_stopped = false;
    config_store.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::ResumeContract {
            status: Success,
        })?),
    })
}

fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    address: HumanAddr,
) -> StdResult<HandleResponse> {
    let mut config_store = TypedStoreMut::attach(&mut deps.storage);
    let mut config: Config = config_store.load(CONFIG_KEY)?;

    enforce_admin(config.clone(), env)?;

    config.admin = address;
    config_store.store(CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::ChangeAdmin {
            status: Success,
        })?),
    })
}

/// YOU SHOULD NEVER USE THIS! This will erase any eligibility for rewards you earned so far
fn emergency_redeem<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
) -> StdResult<HandleResponse> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;
    let mut user: UserInfo = TypedStoreMut::attach(&mut deps.storage)
        .load(env.message.sender.0.as_bytes())
        .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: env.block.height });

    let mut reward_pool: RewardPool =
        TypedStoreMut::attach(&mut deps.storage).load(REWARD_POOL_KEY)?;
    reward_pool.inc_token_supply -= user.locked;
    TypedStoreMut::attach(&mut deps.storage).store(REWARD_POOL_KEY, &reward_pool)?;

    let mut messages = vec![];
    if user.locked > 0 {
        messages.push(secret_toolkit::snip20::transfer_msg(
            env.message.sender.clone(),
            Uint128(user.locked),
            None,
            RESPONSE_BLOCK_SIZE,
            config.inc_token.contract_hash,
            config.inc_token.address,
        )?);
    }

    user = UserInfo { locked: 0, debt: 0, start_height: env.block.height };
    TypedStoreMut::attach(&mut deps.storage).store(env.message.sender.0.as_bytes(), &user)?;

    Ok(HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&LPStakingHandleAnswer::EmergencyRedeem {
            status: Success,
        })?),
    })
}

// Query functions

fn query_pending_rewards<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: &HumanAddr,
    block: u64,
) -> StdResult<Binary> {
    let new_rewards = query_pending(deps, block)?;
    let reward_pool = TypedStore::<RewardPool, S>::attach(&deps.storage).load(REWARD_POOL_KEY)?;
    let user = TypedStore::<UserInfo, S>::attach(&deps.storage)
        .load(address.0.as_bytes())
        .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: 0 });



    to_binary(&LPStakingQueryAnswer::Rewards {
        // This is not necessarily accurate, since we don't validate new_rewards. It is up to
        // the UI to display accurate numbers
        rewards: Uint128(reward_pool.total_rewards),
    })
}

fn query_deposit<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: &HumanAddr,
) -> StdResult<Binary> {
    let user = TypedStore::attach(&deps.storage)
        .load(address.0.as_bytes())
        .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: 0 });

    to_binary(&LPStakingQueryAnswer::Balance {
        amount: Uint128(user.locked),
    })
}

fn query_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&LPStakingQueryAnswer::ContractStatus {
        is_stopped: config.is_stopped,
    })
}

fn query_reward_token<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&LPStakingQueryAnswer::RewardToken {
        token: config.reward_token,
    })
}

fn query_incentivized_token<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
) -> StdResult<Binary> {
    let config: Config = TypedStore::attach(&deps.storage).load(CONFIG_KEY)?;

    to_binary(&LPStakingQueryAnswer::IncentivizedToken {
        token: config.inc_token,
    })
}

// This is only for Keplr support (Viewing Keys)
fn query_token_info<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> StdResult<Binary> {
    let token_info: TokenInfo = TypedStore::attach(&deps.storage).load(TOKEN_INFO_KEY)?;

    to_binary(&LPStakingQueryAnswer::TokenInfo {
        name: token_info.name,
        symbol: token_info.symbol,
        decimals: 1,
        total_supply: None,
    })
}

// Helper functions

fn enforce_admin(config: Config, env: Env) -> StdResult<()> {
    if config.admin != env.message.sender {
        return Err(StdError::generic_err(format!(
            "not an admin: {}",
            env.message.sender
        )));
    }

    Ok(())
}

fn update_rewards<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    newly_allocated: u128,
) -> StdResult<RewardPool> {
    let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
    let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY)?;

    // If there's no new allocation - there is nothing to update because the state of the pool stays the same
    if newly_allocated <= 0 {
        return Ok(reward_pool);
    }

    reward_pool.total_rewards+=newly_allocated;
    rewards_store.store(REWARD_POOL_KEY, &reward_pool)?;

    Ok(reward_pool)
}

fn update_allocation(env: Env, config: Config, hook: Option<Binary>) -> StdResult<HandleResponse> {
    Ok(HandleResponse {
        messages: vec![WasmMsg::Execute {
            contract_addr: config.master.address,
            callback_code_hash: config.master.contract_hash,
            msg: to_binary(&MasterHandleMsg::UpdateAllocation {
                spy_addr: env.contract.address,
                spy_hash: env.contract_code_hash,
                hook,
            })?,
            send: vec![],
        }
            .into()],
        log: vec![],
        data: None,
    })
}



/// validate_end_height returns an error if the lottery ends in the future
fn validate_end_height(end_height: u64, height: u64) -> StdResult<()> {
    if height < end_height {
        Err(StdError::generic_err("Lottery end height is in the future"))
    } else {
        Ok(())
    }
}

/// validate_start_height returns an error if the lottery hasn't started
fn validate_start_height(start_height: u64, height: u64) -> StdResult<()> {
    if height < start_height {
        Err(StdError::generic_err("Lottery start height is in the future"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scrt_finance::lp_staking_msg::LPStakingHandleMsg::{Receive, Redeem, SetViewingKey, CreateViewingKey};
    // use scrt_finance::lp_staking_msg::LPStakingQueryMsg::{Rewards};
    // use scrt_finance::lp_staking_msg::LPStakingReceiveMsg;
    use scrt_finance::types::SecretContract;

    use cosmwasm_std::testing::{
        mock_dependencies, MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR,
    };
    use cosmwasm_std::{
        coins, from_binary, BlockInfo, Coin, ContractInfo, Empty, MessageInfo, StdError, WasmMsg,
    };
    use rand::Rng;
    use scrt_finance::lp_staking_msg::LPStakingHandleAnswer;
    use serde::{Deserialize, Serialize};

    //helper functions


    fn init_helper() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("admin", &[], 1);

        let init_msg = LPStakingInitMsg {
            reward_token: SecretContract {
                address: HumanAddr("sefi".to_string()),
                contract_hash: "reward_token".to_string(),
            },
            inc_token: SecretContract {
                address: HumanAddr("sefi".to_string()),
                contract_hash: "inc_token".to_string(),
            },
            prng_seed: Binary::from("lolz fun yay".as_bytes()),
            viewing_key: "123".to_string(),
            master: SecretContract {
                address: HumanAddr("Master".to_string()),
                contract_hash: "".to_string(),
            },
            token_info: TokenInfo {
                name: "".to_string(),
                symbol: "".to_string(),
            },
        };

        (init(&mut deps, env, init_msg), deps)
    }

    /// Just set sender and sent funds for the message. The rest uses defaults.
    /// The sender will be canonicalized internally to allow developers pasing in human readable senders.
    /// This is intended for use in test code only.
    pub fn mock_env<U: Into<HumanAddr>>(sender: U, sent: &[Coin], height: u64) -> Env {
        Env {
            block: BlockInfo {
                height,
                time: 1_571_797_419,
                chain_id: "secret-testnet".to_string(),
            },
            message: MessageInfo {
                sender: sender.into(),
                sent_funds: sent.to_vec(),
            },
            contract: ContractInfo {
                address: HumanAddr::from(MOCK_CONTRACT_ADDR),
            },
            contract_key: Some("".to_string()),
            contract_code_hash: "".to_string(),
        }
    }

    fn master_update_allocation<S: Storage, A: Api, Q: Querier>(
        deps: &mut Extern<S, A, Q>,
        env: Env,
        spy_address: HumanAddr,
        spy_hash: String,
        hook: Option<Binary>,
    ) -> StdResult<HandleResponse> {

        //Master rewards are fixed for unit-testing
        let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY).unwrap();


        let mut rewards = 100;
        let mut messages = vec![];

        messages.push(snip20::mint_msg(
            spy_address.clone(),
            Uint128(rewards),
            None,
            1,
            config.reward_token.contract_hash.clone(),
            config.reward_token.address.clone(),
        )?);

        // Notify to the spy contract on the new allocation
        messages.push(
            WasmMsg::Execute {
                contract_addr: spy_address.clone(),
                callback_code_hash: spy_hash,
                msg: to_binary(&LPStakingHandleMsg::NotifyAllocation {
                    amount: Uint128(rewards),
                    hook,
                })?,
                send: vec![],
            }
                .into(),
        );

        Ok(HandleResponse {
            messages,
            log: vec![],
            data: None,
        })
    }

    pub enum MasterHandleAnswer {
        Success,
        Failure,
    }

    #[test]

    fn testing_receive(){
        let env = mock_env("admin", &[], 10);
        let (_init_result, mut deps) = init_helper();

        //1) checking if the tokens are from correct inc token address
        let env = mock_env("Not_Sefi", &[], 10);
        let handle_msg = LPStakingHandleMsg::Receive {
            sender: HumanAddr("Sefi".to_string()),
            from: HumanAddr("Batman".to_string()),
            amount: Uint128(1000),
            msg: to_binary(&LPStakingReceiveMsg::Deposit {}).unwrap(),
        };
        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY).unwrap();

        assert_eq!(unwrapped_msg,StdError::generic_err(format!(
            "This token is not supported. Supported: {}, given: {}",
            config.inc_token.address, env.message.sender
        )));


    }

    #[test]
    fn testing_notification_allocation() {

        //1)
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("NotMaster", &[], 10);
        let hook = Some(to_binary(&LPStakingHookMsg::Deposit { from: HumanAddr("User1".to_string()), amount: Uint128(1000) }).unwrap());

        let handle_msg = LPStakingHandleMsg::NotifyAllocation { amount: Uint128(1000), hook };

        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap_err();
        let config: Config = TypedStoreMut::attach(&mut deps.storage).load(CONFIG_KEY).unwrap();


        assert_eq!(unwrapped_msg, StdError::generic_err(
            "you are not allowed to call this function",
        ));
    }


    #[test]
    fn testing_deposit(){
        //1)
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("sefi", &[], 10);
        let handle_msg = LPStakingHandleMsg::Receive {
            sender: HumanAddr("sefi".to_string()),
            from: HumanAddr("Batman".to_string()),
            amount: Uint128(1000),
            msg: to_binary(&LPStakingReceiveMsg::Deposit {}).unwrap(),
        };
        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap();

        //1) checking the amount locked for user(Batman)
        let from = HumanAddr("Batman".to_string());
        let mut user = TypedStore::attach(&deps.storage)
            .load(from.0.as_bytes())
            .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: env.block.height });
        assert_eq!(1000,user.locked);
        assert_eq!(0,user.debt);
        assert_eq!(10,user.start_height);

        //2)Checking Lottery values
        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(1,a_lottery.entries.len());
        assert_eq!(10, a_lottery.duration);
        assert_eq!(2,a_lottery.start_height);
        assert_eq!(12,a_lottery.end_height);

        //3)Checking rewards_pool
        let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
        let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
        assert_eq!(1000,reward_pool.inc_token_supply);
    }

    #[test]
    fn testing_redeem(){
        //1)depositing amount
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("sefi", &[], 10);
        let handle_msg = LPStakingHandleMsg::Receive {
            sender: HumanAddr("sefi".to_string()),
            from: HumanAddr("Batman".to_string()),
            amount: Uint128(1000),
            msg: to_binary(&LPStakingReceiveMsg::Deposit {}).unwrap(),
        };
        handle(&mut deps, env.clone(), handle_msg).unwrap();

        //2)Redeeming
        let env = mock_env("Batman", &[], 10);
        let handle_msg = LPStakingHandleMsg::Redeem {
            amount: Some(Uint128(500))
        };
        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap();


        //1) checking the amount locked for user(Batman)
        let to = HumanAddr("Batman".to_string());
        let mut user = TypedStore::attach(&deps.storage)
            .load(to.0.as_bytes())
            .unwrap_or(UserInfo { locked: 0, debt: 0, start_height: env.block.height });
        assert_eq!(500,user.locked);

        //2)Checking Lottery values
        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(1,a_lottery.entries.len());

        //3)Checking rewards_pool
        let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
        let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
        assert_eq!(500,reward_pool.inc_token_supply);
    }

    #[test]
    fn testing_claim_rewards(){
        //1)depositing amount
        let (_init_result, mut deps) = init_helper();
        let env = mock_env("sefi", &[], 10);
        let handle_msg = LPStakingHandleMsg::Receive {
            sender: HumanAddr("sefi".to_string()),
            from: HumanAddr("Batman".to_string()),
            amount: Uint128(1000),
            msg: to_binary(&LPStakingReceiveMsg::Deposit {}).unwrap(),
        };
        handle(&mut deps, env.clone(), handle_msg).unwrap();

        //2)claiming rewards
        let env = mock_env("Master", &[], 20);
        let handle_msg = LPStakingHandleMsg::ClaimRewards {};
        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap();


        let hook = Some(to_binary(&LPStakingHookMsg::ClaimRewards {}).unwrap());
        let handle_msg = LPStakingHandleMsg::NotifyAllocation { amount:Uint128(5000), hook };
        let unwrapped_msg = handle(&mut deps, env.clone(), handle_msg).unwrap();

        let mut a_lottery = lottery(&mut deps.storage).load().unwrap();
        assert_eq!(1,a_lottery.entries.len());
        assert_eq!(21,a_lottery.start_height);
        assert_eq!(31,a_lottery.end_height);

        let mut rewards_store = TypedStoreMut::attach(&mut deps.storage);
        let mut reward_pool: RewardPool = rewards_store.load(REWARD_POOL_KEY).unwrap();
        assert_eq!(1000,reward_pool.inc_token_supply);
        assert_eq!(0,reward_pool.total_rewards);

    }

}
