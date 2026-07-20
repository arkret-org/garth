use super::*;

pub(super) fn morph_matches_filter(morph: &Morph, filter: &Filter) -> bool {
    match filter {
        Filter::Predicate(predicate) => morph_matches_predicate(morph, predicate),
        Filter::And { and } => and.iter().all(|filter| morph_matches_filter(morph, filter)),
        Filter::Or { or } => or.iter().any(|filter| morph_matches_filter(morph, filter)),
        Filter::Not { not } => !morph_matches_filter(morph, not),
    }
}

pub(super) fn morph_matches_predicate(morph: &Morph, predicate: &FieldFilter) -> bool {
    let actual = morph_field_value(morph, &predicate.field);
    match &predicate.op {
        FilterOp::Exists => {
            let expected = predicate
                .value
                .as_ref()
                .and_then(Value::as_bool)
                .unwrap_or(true);
            actual.is_some() == expected
        }
        FilterOp::Eq => actual.as_ref() == predicate.value.as_ref(),
        FilterOp::Neq => actual.as_ref() != predicate.value.as_ref(),
        FilterOp::In => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(actual), Some(Value::Array(values))) => values.contains(actual),
            _ => false,
        },
        FilterOp::NotIn => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(actual), Some(Value::Array(values))) => !values.contains(actual),
            _ => false,
        },
        FilterOp::Lt | FilterOp::Lte | FilterOp::Gt | FilterOp::Gte => {
            let Some(ordering) = actual
                .as_ref()
                .zip(predicate.value.as_ref())
                .and_then(|(left, right)| compare_json_values(left, right))
            else {
                return false;
            };
            match &predicate.op {
                FilterOp::Lt => ordering == Ordering::Less,
                FilterOp::Lte => matches!(ordering, Ordering::Less | Ordering::Equal),
                FilterOp::Gt => ordering == Ordering::Greater,
                FilterOp::Gte => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => false,
            }
        }
        FilterOp::Contains => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(Value::String(actual)), Some(Value::String(needle))) => actual.contains(needle),
            (Some(Value::Array(values)), Some(needle)) => values.contains(needle),
            (Some(Value::Object(values)), Some(Value::String(key))) => values.contains_key(key),
            _ => false,
        },
        FilterOp::Prefix => match (actual.as_ref(), predicate.value.as_ref()) {
            (Some(Value::String(actual)), Some(Value::String(prefix))) => {
                actual.starts_with(prefix)
            }
            _ => false,
        },
        FilterOp::FullText => match predicate.value.as_ref().and_then(Value::as_str) {
            Some(needle) => value_search_text(actual.as_ref()).contains(&needle.to_lowercase()),
            None => false,
        },
    }
}

pub(super) fn compare_morphs(left: &Morph, right: &Morph, order_by: &[SortSpec]) -> Ordering {
    for sort in order_by {
        let ordering = compare_optional_values(
            morph_field_value(left, &sort.field).as_ref(),
            morph_field_value(right, &sort.field).as_ref(),
            sort.nulls.as_ref(),
            &sort.direction,
        );
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    left.id.cmp(&right.id)
}

pub(super) fn compare_optional_values(
    left: Option<&Value>,
    right: Option<&Value>,
    nulls: Option<&NullsOrder>,
    direction: &SortDirection,
) -> Ordering {
    let null_ordering = |left_is_null: bool| match nulls.unwrap_or(&NullsOrder::Last) {
        NullsOrder::First if left_is_null => Ordering::Less,
        NullsOrder::First => Ordering::Greater,
        NullsOrder::Last if left_is_null => Ordering::Greater,
        NullsOrder::Last => Ordering::Less,
    };

    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => null_ordering(true),
        (Some(_), None) => null_ordering(false),
        (Some(left), Some(right)) => {
            let ordering = compare_json_values(left, right).unwrap_or(Ordering::Equal);
            match direction {
                SortDirection::Asc => ordering,
                SortDirection::Desc => ordering.reverse(),
            }
        }
    }
}

pub(super) fn compare_json_values(left: &Value, right: &Value) -> Option<Ordering> {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => left.as_f64()?.partial_cmp(&right.as_f64()?),
        (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
        (Value::Bool(left), Value::Bool(right)) => Some(left.cmp(right)),
        _ => Some(scalar_value_key(left).cmp(&scalar_value_key(right))),
    }
}

pub(super) fn morph_field_value(morph: &Morph, field: &str) -> Option<Value> {
    match field {
        "id" => Some(json!(morph.id.as_str())),
        "title" => morph.metadata_title().map(|title| json!(title)),
        "summary" => morph.metadata_summary().map(|summary| json!(summary)),
        "morph_type" => Some(json!(morph.morph_type)),
        "state" => morph
            .state
            .as_ref()
            .and_then(|state| serde_json::to_value(state).ok()),
        "created_at" => Some(json!(morph.created_at.to_rfc3339())),
        "updated_at" => morph
            .updated_at
            .map(|updated_at| json!(updated_at.to_rfc3339())),
        "content" => morph
            .content
            .as_ref()
            .and_then(|content| serde_json::to_value(content).ok()),
        _ if field.starts_with("fields.") => morph.fields.get(&field["fields.".len()..]).cloned(),
        _ if field.starts_with("content.") => morph.content.as_ref().and_then(|content| {
            serde_json::to_value(content)
                .ok()
                .and_then(|content| value_at_path(&content, &field["content.".len()..]))
        }),
        _ => morph.fields.get(field).cloned(),
    }
}

pub(super) fn value_at_path(value: &Value, path: &str) -> Option<Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current.clone())
}

pub(super) fn morph_search_text(morph: &Morph) -> String {
    let mut text = String::new();
    if let Some(title) = morph.metadata_title() {
        text.push_str(title);
        text.push(' ');
    }
    if let Some(summary) = morph.metadata_summary() {
        text.push_str(summary);
        text.push(' ');
    }
    if let Some(content) = &morph.content {
        if let Ok(content) = serde_json::to_value(content) {
            text.push_str(&value_search_text(Some(&content)));
        }
        text.push(' ');
    }
    text.push_str(&value_search_text(Some(&json!(morph.fields))));
    text.to_lowercase()
}

pub(super) fn value_search_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Null) | None => String::new(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::String(value)) => value.to_lowercase(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value_search_text(Some(value)))
            .collect::<Vec<_>>()
            .join(" "),
        Some(Value::Object(values)) => values
            .iter()
            .map(|(key, value)| {
                format!("{} {}", key.to_lowercase(), value_search_text(Some(value)))
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

pub(super) fn scalar_value_key(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "unknown".to_owned()),
    }
}

pub(super) fn relation_is_active(relation: &Relation) -> bool {
    !matches!(relation.state, Some(RelationState::Tombstoned))
}

pub(super) fn parse_object_state(value: &str) -> Option<ObjectState> {
    // C47 (spec e10b6ad): `deleted` is no longer a valid Strand / Morph
    // lifecycle state; the only terminal is `redacted`.
    match value {
        "active" => Some(ObjectState::Active),
        "archived" => Some(ObjectState::Archived),
        "redacted" => Some(ObjectState::Redacted),
        _ => None,
    }
}
