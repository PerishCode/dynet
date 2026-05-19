use serde::Serialize;

pub(crate) fn json_string<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to serialize dynet report: {error}"))
}

pub(super) fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    println!("{}", json_string(value)?);
    Ok(())
}
