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
    #[serde(default)]
    pub tag_access_responses: Vec<TagAccessResponse>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TagAccessResponse {
    pub command: String,
    #[serde(default)]
    pub identifier: Option<String>,
    pub response: String,
    #[serde(default)]
    pub data_hex: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagObservation {
    pub epc: String,
    pub tid: String,
    pub antenna_port: u16,
    pub peak_rssi_cdbm: i32,
    pub access_responses: Vec<TagAccessResponse>,
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

impl TagObservation {
    pub fn from_reader_event(event: &ReaderEvent) -> Option<Self> {
        if event.event_type != "tagInventory" {
            return None;
        }
        let tag = event.tag_inventory_event.as_ref()?;
        let epc = tag.epc_hex.as_ref()?.trim().to_ascii_uppercase();
        let tid = tag.tid_hex.as_ref()?.trim().to_ascii_uppercase();
        if !valid_even_hex(&epc) || !valid_even_hex(&tid) || tid.len() * 4 > 255 {
            return None;
        }
        Some(Self {
            epc,
            tid,
            antenna_port: tag.antenna_port?,
            peak_rssi_cdbm: tag.peak_rssi_cdbm?,
            access_responses: tag.tag_access_responses.clone(),
        })
    }
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
        let tid = match tag.tid_hex.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(value) => {
                let value = value.to_ascii_uppercase();
                if !valid_even_hex(&value) || value.len() > 128 {
                    return None;
                }
                Some(value)
            }
        };
        let (tag_key, identity_kind) = if let Some(tid) = &tid {
            (tid.clone(), "tid")
        } else {
            (format!("EPC:{epc}"), "epc")
        };
        let observed_at_ms = DateTime::parse_from_rfc3339(&event.timestamp)
            .ok()?
            .with_timezone(&Utc)
            .timestamp_millis();
        Some(Self {
            tag_key,
            identity_kind,
            tid,
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
    fn parses_an_inventory_event_with_access_responses() {
        let event: ReaderEvent = serde_json::from_value(serde_json::json!({
            "eventType": "tagInventory",
            "timestamp": "2026-07-18T12:00:00.000Z",
            "tagInventoryEvent": {
                "epcHex": "300833B2DDD9014000000000",
                "tidHex": "E28011606000020497CB0065",
                "antennaPort": 1,
                "peakRssiCdbm": -4100,
                "tagAccessResponses": [{
                    "command": "read",
                    "identifier": "verify-epc",
                    "response": "success",
                    "dataHex": "FCA700010000000000000001"
                }]
            }
        }))
        .unwrap();

        let observation = TagObservation::from_reader_event(&event).unwrap();
        assert_eq!(observation.tid, "E28011606000020497CB0065");
        assert_eq!(observation.access_responses.len(), 1);
    }

    #[test]
    fn discovery_falls_back_to_a_stable_epc_key_without_tid() {
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

        let observation = DiscoveryObservation::from_reader_event(&event).unwrap();
        assert_eq!(observation.tag_key, "EPC:11223344556677889900AABB");
        assert_eq!(observation.identity_kind, "epc");
        assert_eq!(observation.tid, None);
        assert_eq!(observation.observed_at_ms, 1_784_376_000_000);
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
