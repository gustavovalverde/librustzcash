use orchard::pczt::{Updater, UpdaterError};
use zcash_protocol::constants::V5_TX_VERSION;

use crate::{Pczt, common::AnchorRequirement, orchard::ParseError};

impl super::Updater {
    /// Updates the Orchard bundle with information in the given closure.
    pub fn update_orchard_with<F>(self, f: F) -> Result<Self, OrchardError>
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

        let mut parsed = orchard
            .into_parsed_with_version(
                crate::orchard::orchard_bundle_version(&global)
                    .ok_or(OrchardError::UnsupportedConsensusBranchId)?,
                AnchorRequirement::NotRequired,
            )
            .map_err(OrchardError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: parsed.reserialize(),
                ironwood,
            },
        })
    }

    /// Updates the Ironwood bundle with information in the given closure.
    pub fn update_ironwood_with<F>(self, f: F) -> Result<Self, OrchardError>
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

        let mut parsed = ironwood
            .into_ironwood_parsed(AnchorRequirement::NotRequired)
            .map_err(OrchardError::Parser)?;

        parsed
            .bundle
            .update_with(f)
            .map_err(OrchardError::Updater)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: parsed.reserialize(),
            },
        })
    }

    /// Sets the Orchard bundle's anchor, or replaces a previously-set one.
    ///
    /// Fails for a v5 transaction, whose anchor is fixed by the Creator and cannot
    /// change. For a v6 transaction, this clears the Orchard bundle's `zkproof` (a
    /// proof commits to the anchor as a circuit public input, so it is invalidated by
    /// an anchor change), and fails if a non-zero-valued spend's `witness` does not
    /// root to `anchor`.
    ///
    /// See [ZIP 374: Anchors and pre-authorization](https://zips.z.cash/zip-0374#anchors-and-pre-authorization).
    pub fn set_orchard_anchor(self, anchor: [u8; 32]) -> Result<Self, OrchardError> {
        let bundle_version = crate::orchard::orchard_bundle_version(&self.pczt.global)
            .ok_or(OrchardError::UnsupportedConsensusBranchId)?;

        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let orchard = set_anchor(global.tx_version, orchard, bundle_version, anchor)?;

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

    /// Sets the Ironwood bundle's anchor, or replaces a previously-set one.
    ///
    /// See [`Self::set_orchard_anchor`] for the rules this follows.
    pub fn set_ironwood_anchor(self, anchor: [u8; 32]) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        let ironwood = set_anchor(
            global.tx_version,
            ironwood,
            orchard::bundle::BundleVersion::ironwood_v3(),
            anchor,
        )?;

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

/// Shared implementation of anchor setting/replacement for the Orchard-protocol
/// bundles (Orchard and Ironwood).
fn set_anchor(
    tx_version: u32,
    bundle: crate::orchard::Bundle,
    bundle_version: orchard::bundle::BundleVersion,
    anchor: [u8; 32],
) -> Result<crate::orchard::Bundle, OrchardError> {
    if tx_version == V5_TX_VERSION {
        return Err(OrchardError::AnchorImmutableForV5);
    }

    let parsed_anchor = orchard::Anchor::from_bytes(anchor)
        .into_option()
        .ok_or(OrchardError::InvalidAnchor)?;

    let mut parsed = bundle
        .into_parsed_with_version(bundle_version, AnchorRequirement::NotRequired)
        .map_err(OrchardError::Parser)?;
    crate::orchard::verify_witnesses_root_to_anchor(&parsed.bundle, parsed_anchor)
        .map_err(OrchardError::InconsistentWitness)?;

    parsed.wire_anchor = Some(anchor);
    let mut bundle = parsed.reserialize();
    bundle.zkproof = None;

    Ok(bundle)
}

/// Errors that can occur while updating the Orchard bundle of a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    /// A v5 transaction's Orchard-protocol anchors are fixed by the Creator and cannot
    /// change.
    AnchorImmutableForV5,
    /// A non-zero-valued spend's `witness` does not root to the given anchor.
    InconsistentWitness(crate::orchard::AnchorConsistencyError),
    /// The given anchor is not a valid Orchard-protocol anchor encoding.
    InvalidAnchor,
    Parser(ParseError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
    Updater(UpdaterError),
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BranchId;

    use crate::{orchard::testing::dummy_action, roles::creator::Creator, roles::updater::Updater};

    use super::OrchardError;

    #[test]
    fn set_orchard_anchor_fails_for_v5() {
        let pczt = Creator::new(BranchId::Nu6.into(), 100, 133, Some([1; 32]), Some([1; 32]))
            .unwrap()
            .build();

        assert!(matches!(
            Updater::new(pczt).set_orchard_anchor([2; 32]),
            Err(OrchardError::AnchorImmutableForV5)
        ));
    }

    #[test]
    fn set_ironwood_anchor_fails_for_v5() {
        let pczt = Creator::new(BranchId::Nu6.into(), 100, 133, Some([1; 32]), Some([1; 32]))
            .unwrap()
            .build();

        assert!(matches!(
            Updater::new(pczt).set_ironwood_anchor([2; 32]),
            Err(OrchardError::AnchorImmutableForV5)
        ));
    }

    #[test]
    fn set_orchard_anchor_succeeds_for_v6_and_clears_proof() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build();
        pczt.orchard.actions.push(dummy_action());
        pczt.orchard.zkproof = Some(alloc::vec![9; 32]);

        let pczt = Updater::new(pczt).set_orchard_anchor([9; 32]).unwrap().pczt;

        assert_eq!(pczt.orchard.anchor, Some([9; 32]));
        assert!(pczt.orchard.zkproof.is_none());
    }

    #[test]
    fn set_ironwood_anchor_succeeds_for_v6_and_clears_proof() {
        let mut pczt = Creator::new(BranchId::Nu6_3.into(), 100, 133, None, None)
            .unwrap()
            .build();
        pczt.ironwood.actions.push(dummy_action());
        pczt.ironwood.zkproof = Some(alloc::vec![9; 32]);

        let pczt = Updater::new(pczt)
            .set_ironwood_anchor([9; 32])
            .unwrap()
            .pczt;

        assert_eq!(pczt.ironwood.anchor, Some([9; 32]));
        assert!(pczt.ironwood.zkproof.is_none());
    }
}
