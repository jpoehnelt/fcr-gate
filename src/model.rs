use chrono::{DateTime, Utc};
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReaderEvent {
    pub event_type: String,
    pub timestamp: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub tag_inventory_event: Option<TagInventoryEvent>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TagInventoryEvent {
    #[serde(default)]
    pub epc_hex: Option<String>,
    #[serde(default)]
    pub tid_hex: Option<String>,
    #[serde(default)]
    pub antenna_port: Option<u16>,
    #[serde(default)]
    pub peak_rssi_cdbm: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryObservation {
    pub tag_key: String,
    pub identity_kind: &'static str,
    pub tid: Option<String>,
    pub epc: String,
    pub antenna_port: u16,
    pub peak_rssi_cdbm: i32,
    pub observed_at_ms: i64,
}

impl DiscoveryObservation {
    pub fn from_reader_event(event: &ReaderEvent) -> Option<Self> {
        if event.event_type != "tagInventory" {
            return None;
        }
        let tag = event.tag_inventory_event.as_ref()?;
        let epc = tag.epc_hex.as_ref()?.trim().to_ascii_uppercase();
        if !valid_even_hex(&epc) {
            return None;
        }
        let tid = tag.tid_hex.as_deref()?.trim().to_ascii_uppercase();
        if !valid_even_hex(&tid) || tid.len() > 128 {
            return None;
        }
        let observed_at_ms = DateTime::parse_from_rfc3339(&event.timestamp)
            .ok()?
            .with_timezone(&Utc)
            .timestamp_millis();
        Some(Self {
            tag_key: tid.clone(),
            identity_kind: "tid",
            tid: Some(tid),
            epc,
            antenna_port: tag.antenna_port?,
            peak_rssi_cdbm: tag.peak_rssi_cdbm?,
            observed_at_ms,
        })
    }
}

fn valid_even_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_inventory_event_with_tid() {
        let event: ReaderEvent = serde_json::from_value(serde_json::json!({
            "eventType": "tagInventory",
            "timestamp": "2026-07-18T12:00:00.000Z",
            "tagInventoryEvent": {
                "epcHex": "300833B2DDD9014000000000",
                "tidHex": "E28011606000020497CB0065",
                "antennaPort": 1,
                "peakRssiCdbm": -4100
            }
        }))
        .unwrap();

        let observation = DiscoveryObservation::from_reader_event(&event).unwrap();
        assert_eq!(observation.tid.as_deref(), Some("E28011606000020497CB0065"));
    }

    #[test]
    fn discovery_requires_a_tid() {
        let event: ReaderEvent = serde_json::from_value(serde_json::json!({
            "eventType": "tagInventory",
            "timestamp": "2026-07-18T12:00:00.000Z",
            "tagInventoryEvent": {
                "epcHex": "11223344556677889900AABB",
                "antennaPort": 1,
                "peakRssiCdbm": -4100
            }
        }))
        .unwrap();

        assert!(DiscoveryObservation::from_reader_event(&event).is_none());
    }

    #[test]
    fn discovery_prefers_tid_over_epc() {
        let event: ReaderEvent = serde_json::from_value(serde_json::json!({
            "eventType": "tagInventory",
            "timestamp": "2026-07-18T12:00:00.000Z",
            "tagInventoryEvent": {
                "epcHex": "11223344556677889900AABB",
                "tidHex": "e28011606000020497cb0065",
                "antennaPort": 1,
                "peakRssiCdbm": -4100
            }
        }))
        .unwrap();

        let observation = DiscoveryObservation::from_reader_event(&event).unwrap();
        assert_eq!(observation.tag_key, "E28011606000020497CB0065");
        assert_eq!(observation.identity_kind, "tid");
        assert_eq!(observation.tid.as_deref(), Some("E28011606000020497CB0065"));
    }
}
