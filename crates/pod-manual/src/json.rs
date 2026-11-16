//! `CLI man --json`: the manual as one JSON object, for a program. It is the
//! model itself, so it keeps what the text drops: the kind of each flag, its
//! status against another tool, and what to type in place of a refused one.

use serde_json::{Value, json};

use crate::model::{Manual, SCHEMA};
use crate::sections::Section;

/// The whole manual: `schema`, then each field of [`Manual`].
pub fn document(manual: &Manual) -> Value {
    let mut doc = serde_json::Map::new();
    doc.insert("schema".into(), json!(SCHEMA));
    if let Ok(Value::Object(m)) = serde_json::to_value(manual) {
        doc.extend(m);
    }
    Value::Object(doc)
}

/// The text of a JSON value, as the writers end it: with a newline.
pub fn text(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
}

/// The manual from its JSON form ([`document`]).
pub fn read(text: &str) -> Result<Manual, String> {
    let mut value: Value = serde_json::from_str(text).map_err(|e| format!("the manual is not JSON: {e}"))?;
    match value.get("schema").and_then(Value::as_u64) {
        Some(n) if n == u64::from(SCHEMA) => {}
        other => return Err(format!("the manual has the schema {other:?}; this reader takes {SCHEMA}")),
    }
    if let Value::Object(m) = &mut value {
        m.remove("schema");
    }
    serde_json::from_value(value).map_err(|e| format!("the manual does not match the model: {e}"))
}

/// One section: a command as its model, a table of facts as its rows, a
/// topic as its blocks.
pub fn section(manual: &Manual, s: &Section) -> Value {
    let body = match (&s.command, s.key.as_str()) {
        (Some(path), _) => {
            let c = manual.command(&path.join(" "));
            // The topics inside the section of the command, as their model.
            let inside: Vec<_> =
                c.map(|c| manual.topics.iter().filter(|t| c.topics.contains(&t.key)).collect()).unwrap_or_default();
            if inside.is_empty() { json!({ "command": c }) } else { json!({ "command": c, "topics": inside }) }
        }
        (None, "environment") => json!({ "variables": manual.facts.variables }),
        (None, "files") => json!({ "files": manual.facts.files }),
        (None, "configuration") => json!({ "config": manual.facts.config }),
        (None, "exit-status") => json!({ "exits": manual.facts.exits }),
        (None, "examples") => json!({ "examples": manual.examples }),
        (None, key) => match manual.facts.tables.iter().find(|t| t.key == key) {
            Some(t) => json!({ "table": t }),
            None => json!({ "topic": { "key": s.key, "heading": s.heading, "blocks": s.blocks } }),
        },
    };
    let mut doc = serde_json::Map::new();
    doc.insert("schema".into(), json!(SCHEMA));
    doc.insert("name".into(), json!(manual.name));
    if let Value::Object(m) = body {
        doc.extend(m);
    }
    Value::Object(doc)
}
