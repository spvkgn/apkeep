use super::OutputFormat;

#[test]
fn output_format_predicates_are_exclusive_and_clone_preserves_format() {
    for (format, json) in [(OutputFormat::Json, true), (OutputFormat::Plaintext, false)] {
        assert_eq!(format.is_json(), json);
        assert_eq!(format.is_plaintext(), !json);
        assert_eq!(format.clone().is_json(), json);
    }
}
