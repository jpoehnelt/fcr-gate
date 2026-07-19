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
}
