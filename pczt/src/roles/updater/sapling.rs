use sapling::pczt::{Updater, UpdaterError};
use zcash_protocol::constants::V5_TX_VERSION;

use crate::{Pczt, common::AnchorRequirement, sapling::ParseError};

impl super::Updater {
    /// Updates the Sapling bundle with information in the given closure.
    pub fn update_sapling_with<F>(self, f: F) -> Result<Self, SaplingError>
    where
        F: FnOnce(Updater<'_>) -> Result<(), UpdaterError>,
    {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut parsed = sapling
            .into_parsed(AnchorRequirement::NotRequired)
            .map_err(SaplingError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(SaplingError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling: parsed.reserialize(),
                orchard,
                ironwood,
            },
        })
    }

    /// Sets the Sapling bundle's anchor, or replaces a previously-set one.
    ///
    /// Fails for a v5 transaction, whose anchor is fixed by the Creator and cannot
    /// change. For a v6 transaction, this clears every Sapling spend's `zkproof` (a
    /// proof commits to the anchor as a circuit public input, so it is invalidated by
    /// an anchor change), and fails if a non-zero-valued spend's `witness` does not
    /// root to `anchor`.
    ///
    /// See [ZIP 374: Anchors and pre-authorization](https://zips.z.cash/zip-0374#anchors-and-pre-authorization).
    pub fn set_sapling_anchor(self, anchor: [u8; 32]) -> Result<Self, SaplingError> {
        if self.pczt.global.tx_version == V5_TX_VERSION {
            return Err(SaplingError::AnchorImmutableForV5);
        }

        let parsed_anchor = sapling::Anchor::from_bytes(anchor)
            .into_option()
            .ok_or(SaplingError::InvalidAnchor)?;

        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let mut parsed = sapling
            .into_parsed(AnchorRequirement::NotRequired)
            .map_err(SaplingError::Parser)?;
        crate::sapling::verify_witnesses_root_to_anchor(&parsed.bundle, parsed_anchor)
            .map_err(SaplingError::InconsistentWitness)?;

        parsed.wire_anchor = Some(anchor);
        let mut sapling = parsed.reserialize();
        for spend in sapling.spends.iter_mut() {
            spend.zkproof = None;
        }

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood,
            },
        })
    }
}

/// Errors that can occur while updating the Sapling bundle of a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    /// A v5 transaction's Sapling anchor is fixed by the Creator and cannot change.
    AnchorImmutableForV5,
    /// A non-zero-valued spend's `witness` does not root to the given anchor.
    InconsistentWitness(crate::sapling::AnchorConsistencyError),
    /// The given anchor is not a valid Sapling anchor encoding.
    InvalidAnchor,
    Parser(ParseError),
    Updater(UpdaterError),
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use incrementalmerkletree::Retention;
    use shardtree::{ShardTree, store::memory::MemoryShardStore};
    use zcash_protocol::consensus::BranchId;

    use crate::{roles::creator::Creator, roles::updater::Updater, sapling::Spend};

    use super::SaplingError;

    /// Derives a valid Sapling value commitment encoding for the given value and
    /// trapdoor, so that hand-crafted `Spend`s pass the structural validity check
    /// applied when parsing (regardless of anchor consistency, which is unrelated).
    fn value_commitment(value: u64, rcv: [u8; 32]) -> [u8; 32] {
        let rcv = sapling::value::ValueCommitTrapdoor::from_bytes(rcv)
            .into_option()
            .unwrap();
        sapling::value::ValueCommitment::derive(sapling::value::NoteValue::from_raw(value), rcv)
            .to_bytes()
    }

    /// A spend with an already-set (fake) `zkproof` and no witness, for testing that
    /// setting the bundle's anchor clears it.
    fn dummy_spend() -> Spend {
        Spend {
            cv: value_commitment(0, [3; 32]),
            nullifier: [2; 32],
            rk: [3; 32],
            zkproof: Some([7; 192]),
            spend_auth_sig: None,
            recipient: None,
            value: None,
            rcm: None,
            rseed: None,
            rcv: None,
            proof_generation_key: None,
            witness: None,
            alpha: None,
            zip32_derivation: None,
            dummy_ask: None,
            proprietary: BTreeMap::new(),
        }
    }

    #[test]
    fn set_sapling_anchor_fails_for_v5() {
        let pczt = Creator::new(BranchId::Nu6.into(), 100, 133, Some([1; 32]), Some([1; 32]))
            .unwrap()
            .build();

        assert!(matches!(
            Updater::new(pczt).set_sapling_anchor([2; 32]),
            Err(SaplingError::AnchorImmutableForV5)
        ));
    }

    #[test]
    fn set_sapling_anchor_succeeds_for_v6_and_clears_proofs() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build();
        pczt.sapling.spends.push(dummy_spend());

        let pczt = Updater::new(pczt).set_sapling_anchor([9; 32]).unwrap().pczt;

        assert_eq!(pczt.sapling.anchor, Some([9; 32]));
        assert!(pczt.sapling.spends[0].zkproof.is_none());
    }

    #[test]
    fn set_sapling_anchor_fails_when_witness_inconsistent() {
        let sapling_extsk = sapling::zip32::ExtendedSpendingKey::master(&[1; 32]);
        let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
        let recipient = sapling_dfvk.default_address().1;
        let value = sapling::value::NoteValue::from_raw(1000);
        let rseed = sapling::Rseed::AfterZip212([4; 32]);
        let note = sapling::Note::from_parts(recipient, value, rseed);

        let (correct_anchor, merkle_path) = {
            let cmu = note.cmu();
            let leaf = sapling::Node::from_cmu(&cmu);
            let mut tree =
                ShardTree::<_, 32, 16>::new(MemoryShardStore::<sapling::Node, u32>::empty(), 100);
            tree.append(leaf, Retention::Marked).unwrap();
            tree.checkpoint(1).unwrap();
            let merkle_path = tree
                .witness_at_checkpoint_depth(0.into(), 0)
                .unwrap()
                .unwrap();
            let anchor: sapling::Anchor = merkle_path.root(leaf).into();
            (anchor.to_bytes(), merkle_path)
        };

        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build();
        pczt.sapling.spends.push(Spend {
            cv: value_commitment(1000, [5; 32]),
            recipient: Some(recipient.to_bytes()),
            value: Some(1000),
            rseed: Some([4; 32]),
            witness: Some((
                0,
                merkle_path
                    .path_elems()
                    .iter()
                    .map(|node| node.to_bytes())
                    .collect::<alloc::vec::Vec<_>>()[..]
                    .try_into()
                    .unwrap(),
            )),
            ..dummy_spend()
        });

        // The correct anchor is accepted.
        let pczt = Updater::new(pczt)
            .set_sapling_anchor(correct_anchor)
            .unwrap()
            .pczt;
        assert_eq!(pczt.sapling.anchor, Some(correct_anchor));
        assert!(pczt.sapling.spends[0].zkproof.is_none());

        // An anchor inconsistent with the existing witness is rejected.
        assert!(matches!(
            Updater::new(pczt).set_sapling_anchor([0; 32]),
            Err(SaplingError::InconsistentWitness(
                crate::sapling::AnchorConsistencyError::WitnessDoesNotRootToAnchor
            ))
        ));
    }
}
