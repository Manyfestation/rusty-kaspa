use kaspa_consensus_core::trusted::TrustedHeader;

use crate::pb as protowire;

// ----------------------------------------------------------------------------
// consensus_core to protowire
// ----------------------------------------------------------------------------

impl From<&TrustedHeader> for protowire::TrustedHeader {
    fn from(item: &TrustedHeader) -> Self {
        Self { header: Some((&*item.header).into()), ghostdag_data: Some((&item.ghostdag).into()) }
    }
}
