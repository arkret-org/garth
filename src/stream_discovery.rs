//! Caller-visible stream discovery. Enumeration anchors are hints; only the
//! admitted per-stream scan/snapshot lane may advance durable content positions.

use std::collections::BTreeSet;

use arkret_http_client::own_station_results::OwnStationStateClient;
use arkret_wire::{RealmId, RealmStreamPage, RealmStreamView};

use crate::{Error, Result};

#[derive(Default)]
struct Enumeration {
    rows: Vec<RealmStreamView>,
    previous_key: Option<Vec<u8>>,
    cursors: BTreeSet<String>,
}

impl Enumeration {
    fn append(&mut self, realm: &RealmId, page: RealmStreamPage) -> Result<Option<String>> {
        page.validate()?;
        if &page.realm_id != realm {
            return Err(Error::Protocol("stream discovery crosses Realm".to_owned()));
        }
        // Validate the entire page before installing any of its rows.
        let mut previous = self.previous_key.clone();
        for row in &page.streams {
            let key = arkret_canonical::canonical_json_bytes(&row.stream_ref)?;
            if previous.as_ref().is_some_and(|old| old >= &key) {
                return Err(Error::Protocol(
                    "stream discovery repeats or reorders a stream".to_owned(),
                ));
            }
            previous = Some(key);
        }
        if let Some(cursor) = &page.next_cursor
            && !self.cursors.insert(cursor.clone())
        {
            return Err(Error::Protocol(
                "stream discovery cursor repeats".to_owned(),
            ));
        }
        self.previous_key = previous;
        self.rows.extend(page.streams);
        Ok(page.next_cursor)
    }
}

/// Enumerate every established stream in one fixed caller-visible generation.
/// No arbitrary page ceiling may make streams beyond the first 500 unreachable.
pub async fn discover_realm_streams(
    client: &OwnStationStateClient,
    realm: &RealmId,
) -> Result<Vec<RealmStreamView>> {
    let mut enumeration = Enumeration::default();
    let mut cursor = None;
    loop {
        let response = client
            .realm_streams_page(realm, cursor.as_deref(), 500)
            .await?;
        cursor = enumeration.append(realm, response.value()?.clone())?;
        client.check_session()?;
        if cursor.is_none() {
            return Ok(enumeration.rows);
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CommitStreamRef, ReadableFloor, ReadableFloorReason};

    use super::*;

    fn rows(count: usize) -> (RealmId, Vec<RealmStreamView>) {
        let realm: RealmId = "ak:realm:AUGIFvQctz4TjQTmvvO4Wdy-xdc5XP2ZnJ5Qpbh4s8Ru"
            .parse()
            .unwrap();
        let head: arkret_wire::RealmCommitId =
            "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4"
                .parse()
                .unwrap();
        let mut rows = (0..count)
            .map(|index| {
                let mut bytes = [0u8; 33];
                bytes[0] = 1;
                bytes[1..9].copy_from_slice(&(index as u64).to_be_bytes());
                RealmStreamView {
                    stream_ref: CommitStreamRef::Circle {
                        realm_id: realm.clone(),
                        circle_id: arkret_wire::CircleId::from_event_id(
                            &arkret_wire::EventId::from_token_bytes(bytes).unwrap(),
                        ),
                    },
                    head_commit_ref: head.clone(),
                    next_position: 3,
                    readable_floor: Some(ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: head.clone(),
                        floor_reason: ReadableFloorReason::StreamStart,
                    }),
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by_cached_key(|row| {
            arkret_canonical::canonical_json_bytes(&row.stream_ref).unwrap()
        });
        (realm, rows)
    }

    fn page(
        realm: &RealmId,
        streams: Vec<RealmStreamView>,
        cursor: Option<&str>,
    ) -> RealmStreamPage {
        RealmStreamPage {
            realm_id: realm.clone(),
            streams,
            next_cursor: cursor.map(str::to_owned),
            has_more: cursor.is_some(),
        }
    }

    #[test]
    fn discovery_crosses_500_and_keeps_each_stream_anchor() {
        let (realm, rows) = rows(1001);
        let mut enumeration = Enumeration::default();
        for (index, chunk) in rows.chunks(500).enumerate() {
            let cursor = match index {
                0 => Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA"),
                1 => Some("ak:cursor:BBBBBBBBBBBBBBBBBBBBBB"),
                _ => None,
            };
            assert_eq!(
                enumeration
                    .append(&realm, page(&realm, chunk.to_vec(), cursor))
                    .unwrap()
                    .as_deref(),
                cursor
            );
        }
        assert_eq!(enumeration.rows, rows);
    }

    #[test]
    fn malformed_continuation_installs_no_rows() {
        let (realm, rows) = rows(3);
        let token = Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA");
        let mut enumeration = Enumeration::default();
        enumeration
            .append(&realm, page(&realm, rows[..1].to_vec(), token))
            .unwrap();
        assert!(
            enumeration
                .append(&realm, page(&realm, rows[1..].to_vec(), token))
                .is_err()
        );
        assert_eq!(enumeration.rows.len(), 1);
        assert!(
            enumeration
                .append(&realm, page(&realm, rows[..1].to_vec(), None))
                .is_err()
        );
        assert_eq!(enumeration.rows.len(), 1);
        let mut wrong = page(&realm, rows[1..].to_vec(), None);
        wrong.streams[0].next_position = 0;
        assert!(enumeration.append(&realm, wrong).is_err());
        assert_eq!(enumeration.rows.len(), 1);
    }

    #[tokio::test]
    async fn ordinary_bound_client_follows_real_http_discovery_continuations() {
        let (realm, rows) = rows(1001);
        let bodies = rows
            .chunks(500)
            .enumerate()
            .map(|(index, chunk)| {
                let cursor = match index {
                    0 => Some("ak:cursor:AAAAAAAAAAAAAAAAAAAAAA"),
                    1 => Some("ak:cursor:BBBBBBBBBBBBBBBBBBBBBB"),
                    _ => None,
                };
                serde_json::to_value(page(&realm, chunk.to_vec(), cursor)).unwrap()
            })
            .collect();
        let (client, server, observed) = crate::own_station_results::tests::observed_client(bodies);
        assert_eq!(discover_realm_streams(&client, &realm).await.unwrap(), rows);
        server.join().unwrap();
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| request.starts_with(
            &format!("get /_arkret/self/realms/{realm}/streams?").to_ascii_lowercase()
        )));
        assert!(!requests[0].contains("cursor="));
        assert!(requests[1].contains("cursor=ak%3acursor%3aaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(requests[2].contains("cursor=ak%3acursor%3abbbbbbbbbbbbbbbbbbbbbb"));
    }
}
