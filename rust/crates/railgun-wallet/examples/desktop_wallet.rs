//! End-to-end example of the wallet building blocks a desktop app integrates
//! today: create/restore an encrypted RAILGUN wallet, derive its 0zk + 0x
//! addresses, and export/import a view-only (shareable viewing) key.
//!
//! Run with:  cargo run -p railgun-wallet --example desktop_wallet
//!
//! NOTE: this covers the offline/key-management surface only. Syncing balances
//! from chain and creating spend proofs require integrator-supplied traits and a
//! Groth16 backend — see the README "What you must provide" section.

use railgun_db::Database;
use railgun_key_derivation::Mnemonic;
use railgun_models::engine_types::Chain;
use railgun_wallet::{RailgunWallet, ViewOnlyWallet};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Storage. Use `Database::in_memory()` for tests; back it with a real
    //    `KvStore` impl (e.g. redb) in production. Wallet secrets are stored
    //    AES-256-GCM-encrypted under `encryption_key` (derive this from the
    //    user's OS keychain / password — do not hard-code it).
    let mut db = Database::in_memory();
    let encryption_key = [0x11u8; 32];

    // 2. Create a wallet from a fresh 12-word mnemonic at account index 0.
    let mnemonic = Mnemonic::generate(128);
    assert!(Mnemonic::validate(&mnemonic));
    let wallet = RailgunWallet::from_mnemonic(&mut db, &encryption_key, &mnemonic, 0, None)?;

    // 3. Addresses. The 0zk address is chain-scoped; the 0x address is the
    //    matching EVM account (m/44'/60'/0'/0/index).
    let ethereum = Chain {
        chain_type: 0,
        id: 1,
    };
    let zk_address = wallet.wallet.get_address(Some(ethereum));
    let evm_address = wallet.get_chain_address(&db, &encryption_key, None)?;
    println!("0zk address : {zk_address}");
    println!("0x  address : {evm_address}");

    // 4. Restore later from encrypted storage by wallet id (no mnemonic needed
    //    to load; the mnemonic is required again only to spend).
    let id = wallet.wallet.id.clone();
    let restored = RailgunWallet::load_existing(&db, &encryption_key, &id, None)?;
    assert_eq!(restored.wallet.get_address(Some(ethereum)), zk_address);

    // 5. Export a view-only (shareable viewing) key and rebuild a watch-only
    //    wallet from it — same addresses, cannot spend.
    let shareable = wallet.wallet.generate_shareable_viewing_key()?;
    let view_only =
        ViewOnlyWallet::from_shareable_viewing_key(&mut db, &encryption_key, &shareable, None)?;
    assert_eq!(view_only.wallet.get_address(Some(ethereum)), zk_address);
    println!(
        "view-only address matches: {}",
        view_only.wallet.get_address(Some(ethereum))
    );

    Ok(())
}
