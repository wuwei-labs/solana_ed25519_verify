//! Integration tests using solana-program-test to verify Ed25519 signature
//! verification via Solana syscalls.

use solana_program_test::{processor, BanksTransactionResultWithMetadata, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

/// Program ID for the test program
fn program_id() -> Pubkey {
    Pubkey::new_unique()
}

/// Build instruction data: pubkey (32) + signature (64) + message (variable)
fn build_instruction_data(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(96 + message.len());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    data
}

#[tokio::test]
async fn test_valid_signature() {
    let program_id = program_id();

    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        processor!(ed25519_verify_test_program::process_instruction),
    );

    // Start the test environment
    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Create a keypair and sign a message
    let signing_keypair = Keypair::new();
    let message = b"Hello, Solana! Testing Ed25519 signature verification.";
    let signature = signing_keypair.sign_message(message);
    let pubkey_bytes = signing_keypair.pubkey().to_bytes();

    // Build the instruction
    let instruction_data = build_instruction_data(&pubkey_bytes, &signature.into(), message);
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

    // Create and send the transaction
    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    // Transaction should succeed for valid signature
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_ok(), "Valid signature should succeed: {:?}", result);
}

#[tokio::test]
async fn test_invalid_signature_wrong_message() {
    let program_id = program_id();

    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        processor!(ed25519_verify_test_program::process_instruction),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Create a keypair and sign a message
    let signing_keypair = Keypair::new();
    let original_message = b"Original message";
    let signature = signing_keypair.sign_message(original_message);
    let pubkey_bytes = signing_keypair.pubkey().to_bytes();

    // Use a different message for verification
    let wrong_message = b"Different message";
    let instruction_data = build_instruction_data(&pubkey_bytes, &signature.into(), wrong_message);
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    // Transaction should fail for invalid signature
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_err(), "Invalid signature (wrong message) should fail");
}

#[tokio::test]
async fn test_invalid_signature_wrong_key() {
    let program_id = program_id();

    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        processor!(ed25519_verify_test_program::process_instruction),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Sign with one keypair
    let signing_keypair = Keypair::new();
    let message = b"Test message";
    let signature = signing_keypair.sign_message(message);

    // Use a different keypair's pubkey for verification
    let wrong_keypair = Keypair::new();
    let wrong_pubkey_bytes = wrong_keypair.pubkey().to_bytes();

    let instruction_data = build_instruction_data(&wrong_pubkey_bytes, &signature.into(), message);
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    // Transaction should fail for mismatched pubkey
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_err(), "Invalid signature (wrong pubkey) should fail");
}

#[tokio::test]
async fn test_instruction_data_too_short() {
    let program_id = program_id();

    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        processor!(ed25519_verify_test_program::process_instruction),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Send instruction data that's too short (less than 96 bytes)
    let short_data = vec![0u8; 50];
    let instruction = Instruction::new_with_bytes(program_id, &short_data, vec![]);

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    // Transaction should fail due to short instruction data
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_err(), "Short instruction data should fail");
}

#[tokio::test]
async fn test_empty_message() {
    let program_id = program_id();

    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        processor!(ed25519_verify_test_program::process_instruction),
    );

    let (banks_client, payer, recent_blockhash) = program_test.start().await;

    // Sign an empty message
    let signing_keypair = Keypair::new();
    let message: &[u8] = b"";
    let signature = signing_keypair.sign_message(message);
    let pubkey_bytes = signing_keypair.pubkey().to_bytes();

    let instruction_data = build_instruction_data(&pubkey_bytes, &signature.into(), message);
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
    transaction.sign(&[&payer], recent_blockhash);

    // Empty message should still work
    let result = banks_client.process_transaction(transaction).await;
    assert!(result.is_ok(), "Empty message signature should succeed: {:?}", result);
}

/// Helper to process transaction and return compute units consumed
async fn process_and_get_compute_units(
    banks_client: &mut solana_program_test::BanksClient,
    transaction: Transaction,
) -> Result<u64, Box<dyn std::error::Error>> {
    let result: BanksTransactionResultWithMetadata = banks_client
        .process_transaction_with_metadata(transaction)
        .await?;

    if let Some(err) = result.result.err() {
        return Err(format!("Transaction failed: {:?}", err).into());
    }

    let compute_units = result
        .metadata
        .ok_or("No metadata")?
        .compute_units_consumed;

    Ok(compute_units)
}

/// Check if BPF program exists
fn bpf_program_exists() -> bool {
    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/deploy/ed25519_verify_test_program.so");
    path.exists()
}

/// This test requires the BPF program to be built and SBF_OUT_DIR set.
/// Run with: SBF_OUT_DIR=target/deploy cargo test test_compute_units_bpf -- --nocapture
#[tokio::test]
async fn test_compute_units_bpf() {
    if !bpf_program_exists() {
        eprintln!("\n========================================");
        eprintln!("SKIPPING BPF COMPUTE UNITS TEST");
        eprintln!("Run 'cargo build-sbf' first");
        eprintln!("========================================\n");
        return;
    }

    // Check if SBF_OUT_DIR is set
    if std::env::var("SBF_OUT_DIR").is_err() {
        eprintln!("\n========================================");
        eprintln!("SKIPPING BPF COMPUTE UNITS TEST");
        eprintln!("Run with: SBF_OUT_DIR=target/deploy cargo test test_compute_units_bpf -- --nocapture");
        eprintln!("========================================\n");
        return;
    }

    let program_id = program_id();

    // Load BPF program from SBF_OUT_DIR
    let program_test = ProgramTest::new(
        "ed25519_verify_test_program",
        program_id,
        None, // Load from SBF_OUT_DIR
    );

    let (mut banks_client, payer, _recent_blockhash) = program_test.start().await;

    println!("\n========================================");
    println!("COMPUTE UNITS (BPF) BY MESSAGE SIZE");
    println!("========================================");

    // Test various message sizes
    let message_sizes = [0, 32, 64, 128, 256, 512, 1024];

    for size in message_sizes {
        let signing_keypair = Keypair::new();
        let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let signature = signing_keypair.sign_message(&message);
        let pubkey_bytes = signing_keypair.pubkey().to_bytes();

        let instruction_data = build_instruction_data(&pubkey_bytes, &signature.into(), &message);
        let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

        let recent_blockhash = banks_client
            .get_latest_blockhash()
            .await
            .expect("get blockhash");

        let mut transaction = Transaction::new_with_payer(&[instruction], Some(&payer.pubkey()));
        transaction.sign(&[&payer], recent_blockhash);

        let compute_units = process_and_get_compute_units(&mut banks_client, transaction)
            .await
            .expect("Transaction should succeed");

        println!("Message size: {:>5} bytes -> {:>6} CU", size, compute_units);
    }

    println!("========================================\n");
}
