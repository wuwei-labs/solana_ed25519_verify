//! Minimal Solana program for testing Ed25519 signature verification via syscalls.
//!
//! Instruction data format:
//! - bytes 0..32: pubkey (32 bytes)
//! - bytes 32..96: signature (64 bytes)
//! - bytes 96..: message (variable length)

use solana_program::{
    account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, msg, pubkey::Pubkey,
};

entrypoint!(process_instruction);

pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Ed25519 verify test program");

    // Parse instruction data
    if instruction_data.len() < 96 {
        msg!("Instruction data too short");
        return Err(solana_program::program_error::ProgramError::InvalidInstructionData);
    }

    let pubkey: &[u8; 32] = instruction_data[0..32]
        .try_into()
        .map_err(|_| solana_program::program_error::ProgramError::InvalidInstructionData)?;

    let signature: &[u8; 64] = instruction_data[32..96]
        .try_into()
        .map_err(|_| solana_program::program_error::ProgramError::InvalidInstructionData)?;

    let message = &instruction_data[96..];

    msg!("Verifying signature...");

    // Call verify_signature - this uses syscalls on BPF
    match solana_ed25519_verify::verify_signature(pubkey, signature, message) {
        Ok(true) => {
            msg!("Signature valid!");
            Ok(())
        }
        Ok(false) => {
            msg!("Signature invalid!");
            Err(solana_program::program_error::ProgramError::InvalidArgument)
        }
        Err(e) => {
            msg!("Verification error: {}", e);
            Err(solana_program::program_error::ProgramError::InvalidArgument)
        }
    }
}
