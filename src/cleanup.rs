use std::time::{SystemTime, UNIX_EPOCH};

use crate::routes::{account_settings, delete, login, mfa};

pub fn run() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Unexpected error: failed to get system time")
        .as_secs();
    for pending in account_settings::PENDING_MFAS.iter() {
        if now - pending.value().time > 3600 {
            account_settings::PENDING_MFAS.remove(pending.key());
        }
    }
    for pending in delete::PENDING_DELETES.iter() {
        if now - pending.value().time > 3600 {
            delete::PENDING_DELETES.remove(pending.key());
        }
    }
    for pending in login::PENDING_MFAS.iter() {
        if now - pending.value().time > 3600 {
            login::PENDING_MFAS.remove(pending.key());
        }
    }
    for pending in mfa::PENDING_MFA_ENABLES.iter() {
        if now - pending.value().time > 3600 {
            mfa::PENDING_MFA_ENABLES.remove(pending.key());
        }
    }
    for pending in mfa::PENDING_MFA_DISABLES.iter() {
        if now - pending.value().time > 3600 {
            mfa::PENDING_MFA_DISABLES.remove(pending.key());
        }
    }
}
