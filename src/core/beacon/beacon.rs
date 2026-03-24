/*
    Copyright (C) 2026 GGroup and Gteam

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::sync::atomic::{AtomicU64, Ordering};
use chrono::{Datelike, Timelike, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use x25519_dalek::PublicKey as XPublicKey;

const VERSION: u8 = 1;
static SEQ_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn gen_magic() -> u32 {
    let now = Utc::now();
    let hour  = now.hour() as u32;
    let year  = now.year() as u32;
    let day   = now.day() as u32;
    let month = now.month() as u32;

    let number_day_hour = day + hour;
    let number_first_day = day % 10;

    let base: u64 = (year as u64) * 1_000_000
        + (month as u64) * 10_000
        + (day as u64) * 100
        + hour as u64;

    let mut magic: u64 = base.wrapping_mul(number_day_hour as u64 + 1)
        .wrapping_add(number_first_day as u64)
        .wrapping_mul(month as u64 + 7)
        ^ (base >> 17)
        ^ (base << 11)
        ^ ((year as u64 + day as u64) << 23);

    magic = magic ^ (magic >> 13);
    magic = magic.wrapping_mul(month as u64 + day as u64 + hour as u64 + 3);
    magic = magic ^ (magic << 7) ^ (magic >> 19);

    magic as u32
}

pub fn generate_identity() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn generate_node_x25519_key() -> (StaticSecret, XPublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = XPublicKey::from(&secret);
    (secret, public)
}

pub fn node_id() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

pub fn gen_shared_secret(secret: EphemeralSecret, remote_public: &PublicKey) -> SharedSecret {
    secret.diffie_hellman(remote_public)
}

pub fn init_seq() {
    let mut rng = OsRng;
    let random_offset = rng.next_u64();
    let start_time = (Utc::now().timestamp() as u64).wrapping_mul(1_000) + (random_offset % 1000);
    SEQ_COUNTER.store(start_time, Ordering::SeqCst);
}

pub fn get_next_seq() -> u64 {
    SEQ_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn get_timestamp() -> u64 {
    Utc::now().timestamp_millis() as u64
}

pub fn derive_encryption_key(signing_key: &SigningKey) -> (StaticSecret, XPublicKey) {
    let mut hasher = Sha512::new();
    hasher.update(b"GMesh-Node-X25519-Key-Derivation-v1");
    hasher.update(signing_key.to_bytes());
    let hash = hasher.finalize();

    let mut x25519_seed = [0u8; 32];
    x25519_seed.copy_from_slice(&hash[..32]);

    let secret = StaticSecret::from(x25519_seed);
    let public = XPublicKey::from(&secret);

    (secret, public)
}

pub fn sign_packet(signing_key: &SigningKey, data: &[u8]) -> [u8; 64] {
    signing_key.sign(data).to_bytes()
}