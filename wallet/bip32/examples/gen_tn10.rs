// Generates a fresh Kaspa testnet-10 (tn10) HD wallet: BIP39 mnemonic + first receive address.
// Standard Kaspa derivation path: m/44'/111111'/0'/0/0
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey, SecretKeyExt, WordCount};
use std::str::FromStr;

fn main() {
    let mnemonic = Mnemonic::random(WordCount::Words24, Language::English).expect("mnemonic");
    let phrase = mnemonic.phrase_string();
    let seed = mnemonic.to_seed("");

    let xprv = ExtendedPrivateKey::<SecretKey>::new(seed).expect("xprv");
    let path = DerivationPath::from_str("m/44'/111111'/0'/0/0").expect("path");
    let derived = xprv.derive_path(&path).expect("derive");

    let public_key = derived.private_key().get_public_key();
    let (xonly, _) = public_key.x_only_public_key();
    let address = Address::new(Prefix::Testnet, Version::PubKey, &xonly.serialize());

    println!("=== Kaspa testnet-10 (tn10) wallet ===");
    println!("MNEMONIC (24 words): {phrase}");
    println!("DERIVATION_PATH: m/44'/111111'/0'/0/0");
    println!("RECEIVE_ADDRESS: {address}");
}
