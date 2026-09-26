//! An NSM that signs for real, echoing back whatever it was asked to bind.
//!
//! Copied into four test files before it lived here. A fake returning a canned
//! document would let an endpoint pass while binding the wrong certificate —
//! precisely the bug those tests exist to catch — so this builds the payload
//! from the request and signs it with a chain it mints.

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// See [`super::PCR0`].
use super::PCR0;

#[derive(Debug)]
pub struct SigningNsm {
    chain: nitro_attestation::testing::TestChain,
    pcrs: Mutex<Vec<nitro_nsm::Pcr>>,
    /// Counted, so successive draws differ. A device that returned the same
    /// bytes every time would mint one tenant id for every passkey, which is
    /// the isolation property quietly inverted.
    draws: AtomicU64,
}

impl SigningNsm {
    pub fn new() -> Result<Self> {
        Ok(SigningNsm {
            chain: nitro_attestation::testing::TestChain::new()?,
            // Registers behave like the device's: 0-15 locked from the start,
            // 16 free until a guest is measured into it, and documents list
            // only the locked ones. So PCR16 appears in a document here for the
            // reason it appears in a real one.
            pcrs: Mutex::new(
                (0..32)
                    .map(|i| nitro_nsm::Pcr {
                        locked: i < 16,
                        value: if i == 0 {
                            PCR0.to_vec()
                        } else {
                            nitro_nsm::PCR_ZERO.to_vec()
                        },
                    })
                    .collect(),
            ),
            draws: AtomicU64::new(0),
        })
    }

    /// The root a client must trust to verify what this signs.
    pub fn trust_root(&self) -> Vec<u8> {
        self.chain.root_der().to_vec()
    }
}

impl nitro_nsm::Nsm for SigningNsm {
    fn get_random(&self, buf: &mut [u8]) -> Result<()> {
        let draw = self.draws.fetch_add(1, Ordering::SeqCst);
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8)
                .wrapping_mul(7)
                .wrapping_add(3)
                .wrapping_add(draw as u8);
        }
        Ok(())
    }

    fn attest(&self, request: &nitro_nsm::AttestationRequest) -> Result<Vec<u8>> {
        let pcrs = self
            .pcrs
            .lock()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, pcr)| pcr.locked)
            .map(|(index, pcr)| (index as u32, pcr.value.clone()))
            .collect();
        self.chain
            .document_with_pcrs(request.user_data.clone(), request.nonce.clone(), pcrs)
    }

    fn describe_pcr(&self, index: u16) -> Result<nitro_nsm::Pcr> {
        self.pcrs
            .lock()
            .unwrap()
            .get(index as usize)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))
    }

    fn extend_pcr(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.value = nitro_nsm::pcr_extend(&pcr.value, data);
        Ok(pcr.value.clone())
    }

    fn lock_pcr(&self, index: u16) -> Result<()> {
        let mut pcrs = self.pcrs.lock().unwrap();
        let pcr = pcrs
            .get_mut(index as usize)
            .ok_or_else(|| anyhow::anyhow!("no PCR{index}"))?;
        anyhow::ensure!(!pcr.locked, "PCR{index} is read-only");
        pcr.locked = true;
        Ok(())
    }

    fn describe(&self) -> String {
        "signing test NSM".into()
    }
}
