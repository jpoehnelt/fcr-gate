use std::{collections::HashMap, time::Instant};

use crate::{model::TagObservation, store::Encoding};

const VERIFY_IDENTIFIER: &str = "verify-epc";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    CandidateReady { tid: String },
    AccessVerified { tid: String, epc: String },
    AccessFailed { tid: String, reason: String },
    Completed { tid: String, epc: String },
    Conflict { tid: String, observed_epc: String },
}

#[derive(Clone, Debug)]
struct Candidate {
    count: u32,
    last_seen: Instant,
}

#[derive(Debug)]
struct InFlight {
    tid: String,
    started_at: Instant,
}

#[derive(Debug)]
pub struct Engine {
    antenna_port: u16,
    default_epc: String,
    min_rssi_cdbm: i32,
    confirm_reads: u32,
    confirm_window: std::time::Duration,
    recent: HashMap<String, Candidate>,
    in_flight: Option<InFlight>,
}

impl Engine {
    pub fn new(
        antenna_port: u16,
        default_epc: String,
        min_rssi_cdbm: i32,
        confirm_reads: u32,
        confirm_window: std::time::Duration,
    ) -> Self {
        Self {
            antenna_port,
            default_epc,
            min_rssi_cdbm,
            confirm_reads,
            confirm_window,
            recent: HashMap::new(),
            in_flight: None,
        }
    }

    pub fn observe(
        &mut self,
        observation: &TagObservation,
        assignment: Option<&Encoding>,
        now: Instant,
    ) -> Action {
        if observation.antenna_port != self.antenna_port {
            return Action::None;
        }

        if !observation.access_responses.is_empty()
            && self
                .in_flight
                .as_ref()
                .is_some_and(|in_flight| in_flight.tid == observation.tid)
        {
            if let Some(assignment) = assignment {
                return classify_access(observation, assignment);
            }
        }

        if let Some(assignment) = assignment {
            if observation.epc == assignment.assigned_epc {
                if assignment.status == "completed" {
                    return Action::None;
                }
                return Action::Completed {
                    tid: observation.tid.clone(),
                    epc: observation.epc.clone(),
                };
            }
            if observation.epc != self.default_epc
                && !matches!(assignment.status.as_str(), "conflict" | "repair")
            {
                return Action::Conflict {
                    tid: observation.tid.clone(),
                    observed_epc: observation.epc.clone(),
                };
            }
        }

        let repair_authorized = assignment.is_some_and(|assignment| assignment.status == "repair");
        if (observation.epc != self.default_epc && !repair_authorized)
            || observation.peak_rssi_cdbm < self.min_rssi_cdbm
        {
            return Action::None;
        }

        self.recent
            .retain(|_, candidate| now.duration_since(candidate.last_seen) <= self.confirm_window);
        let candidate_count = {
            let candidate = self
                .recent
                .entry(observation.tid.clone())
                .or_insert(Candidate {
                    count: 0,
                    last_seen: now,
                });
            if now.duration_since(candidate.last_seen) > self.confirm_window {
                candidate.count = 0;
            }
            candidate.count = candidate.count.saturating_add(1);
            candidate.last_seen = now;
            candidate.count
        };

        if self.in_flight.is_some() || self.recent.len() != 1 {
            return Action::None;
        }
        if candidate_count >= self.confirm_reads {
            Action::CandidateReady {
                tid: observation.tid.clone(),
            }
        } else {
            Action::None
        }
    }

    pub fn set_in_flight(&mut self, tid: String, now: Instant) {
        self.in_flight = Some(InFlight {
            tid,
            started_at: now,
        });
    }

    pub fn clear_in_flight(&mut self, tid: &str) {
        if self
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.tid == tid)
        {
            self.in_flight = None;
        }
        self.recent.remove(tid);
    }

    pub fn expire_in_flight(
        &mut self,
        now: Instant,
        timeout: std::time::Duration,
    ) -> Option<String> {
        let expired = self
            .in_flight
            .as_ref()
            .filter(|in_flight| now.duration_since(in_flight.started_at) >= timeout)?;
        let tid = expired.tid.clone();
        self.clear_in_flight(&tid);
        Some(tid)
    }
}

fn classify_access(observation: &TagObservation, assignment: &Encoding) -> Action {
    for index in 0..6 {
        let identifier = format!("write-epc-{index}");
        let Some(response) = observation
            .access_responses
            .iter()
            .find(|response| response.identifier.as_deref() == Some(identifier.as_str()))
        else {
            return Action::AccessFailed {
                tid: observation.tid.clone(),
                reason: format!("missing response for {identifier}"),
            };
        };
        if response.command != "write" || response.response != "success" {
            return Action::AccessFailed {
                tid: observation.tid.clone(),
                reason: format!(
                    "{identifier}: command={}, response={}",
                    response.command, response.response
                ),
            };
        }
    }

    let Some(verify) = observation
        .access_responses
        .iter()
        .find(|response| response.identifier.as_deref() == Some(VERIFY_IDENTIFIER))
    else {
        return Action::AccessFailed {
            tid: observation.tid.clone(),
            reason: "missing EPC read-back response".into(),
        };
    };
    let data = verify.data_hex.as_deref().unwrap_or_default();
    if verify.command != "read"
        || verify.response != "success"
        || !data.eq_ignore_ascii_case(&assignment.assigned_epc)
    {
        return Action::AccessFailed {
            tid: observation.tid.clone(),
            reason: format!(
                "EPC read-back failed: command={}, response={}, data={data}",
                verify.command, verify.response
            ),
        };
    }

    Action::AccessVerified {
        tid: observation.tid.clone(),
        epc: assignment.assigned_epc.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::model::TagAccessResponse;

    use super::*;

    fn observation(tid: &str, epc: &str, rssi: i32) -> TagObservation {
        TagObservation {
            epc: epc.into(),
            tid: tid.into(),
            antenna_port: 1,
            peak_rssi_cdbm: rssi,
            access_responses: Vec::new(),
        }
    }

    fn assignment(tid: &str, epc: &str) -> Encoding {
        Encoding {
            sequence: 1,
            tid: tid.into(),
            assigned_epc: epc.into(),
            status: "pending".into(),
            attempts: 0,
            retry_after_ms: 0,
            last_error: None,
        }
    }

    #[test]
    fn requires_repeated_unambiguous_reads() {
        let mut engine = Engine::new(
            1,
            "300833B2DDD9014000000000".into(),
            -5000,
            3,
            Duration::from_secs(1),
        );
        let start = Instant::now();
        let tag = observation("E2801111", "300833B2DDD9014000000000", -4000);

        assert_eq!(engine.observe(&tag, None, start), Action::None);
        assert_eq!(
            engine.observe(&tag, None, start + Duration::from_millis(100)),
            Action::None
        );
        assert_eq!(
            engine.observe(&tag, None, start + Duration::from_millis(200)),
            Action::CandidateReady {
                tid: "E2801111".into()
            }
        );
    }

    #[test]
    fn a_second_default_tag_blocks_encoding() {
        let mut engine = Engine::new(
            1,
            "300833B2DDD9014000000000".into(),
            -5000,
            2,
            Duration::from_secs(1),
        );
        let start = Instant::now();
        let first = observation("E2801111", "300833B2DDD9014000000000", -4000);
        let second = observation("E2802222", "300833B2DDD9014000000000", -4000);

        assert_eq!(engine.observe(&first, None, start), Action::None);
        assert_eq!(
            engine.observe(&second, None, start + Duration::from_millis(10)),
            Action::None
        );
        assert_eq!(
            engine.observe(&first, None, start + Duration::from_millis(20)),
            Action::None
        );
    }

    #[test]
    fn verifies_every_write_and_read_back() {
        let epc = "FCA700010000000000000001";
        let assigned = assignment("E2801111", epc);
        let mut tag = observation("E2801111", "300833B2DDD9014000000000", -4000);
        tag.access_responses = (0..6)
            .map(|index| TagAccessResponse {
                command: "write".into(),
                identifier: Some(format!("write-epc-{index}")),
                response: "success".into(),
                data_hex: None,
            })
            .chain(std::iter::once(TagAccessResponse {
                command: "read".into(),
                identifier: Some("verify-epc".into()),
                response: "success".into(),
                data_hex: Some(epc.into()),
            }))
            .collect();

        assert_eq!(
            classify_access(&tag, &assigned),
            Action::AccessVerified {
                tid: "E2801111".into(),
                epc: epc.into()
            }
        );
    }

    #[test]
    fn an_in_flight_write_expires() {
        let mut engine = Engine::new(
            1,
            "300833B2DDD9014000000000".into(),
            -5000,
            3,
            Duration::from_secs(1),
        );
        let start = Instant::now();
        engine.set_in_flight("E2801111".into(), start);

        assert_eq!(
            engine.expire_in_flight(start + Duration::from_secs(2), Duration::from_secs(3)),
            None
        );
        assert_eq!(
            engine.expire_in_flight(start + Duration::from_secs(3), Duration::from_secs(3)),
            Some("E2801111".into())
        );
    }

    #[test]
    fn explicit_repair_can_rewrite_a_partial_epc() {
        let mut engine = Engine::new(
            1,
            "300833B2DDD9014000000000".into(),
            -5000,
            2,
            Duration::from_secs(1),
        );
        let start = Instant::now();
        let tag = observation("E2801111", "DEADBEEF0000000000000001", -4000);
        let mut assigned = assignment("E2801111", "FCA700010000000000000001");
        assigned.status = "repair".into();

        assert_eq!(engine.observe(&tag, Some(&assigned), start), Action::None);
        assert_eq!(
            engine.observe(&tag, Some(&assigned), start + Duration::from_millis(100)),
            Action::CandidateReady {
                tid: "E2801111".into()
            }
        );
    }
}
