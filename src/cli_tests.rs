use super::*;
use std::str::FromStr;

#[test]
fn source_names_round_trip_and_google_play_remains_default() {
    for source in DownloadSource::value_variants() {
        let name = source.to_string();
        assert!(<DownloadSource as FromStr>::from_str(&name).unwrap() == *source);
        let matches = app()
            .try_get_matches_from(["apkeep", "-a", "com.example.app", "-l", "-d", &name])
            .unwrap();
        assert!(matches.get_one::<DownloadSource>("download_source") == Some(source));
    }
    assert!(<DownloadSource as FromStr>::from_str("ru_store").is_err());
    assert!(<DownloadSource as FromStr>::from_str("RU-STORE").is_err());
    let matches = app()
        .try_get_matches_from(["apkeep", "-a", "com.example.app", "-l"])
        .unwrap();
    assert!(
        matches.get_one::<DownloadSource>("download_source") == Some(&DownloadSource::GooglePlay)
    );
    assert_eq!(matches.get_one::<usize>("parallel"), Some(&4));
    assert_eq!(matches.get_one::<u64>("sleep_duration"), Some(&0));
    assert_eq!(matches.get_one::<usize>("field"), Some(&1));
}

#[test]
fn app_and_csv_conflict_and_missing_input_or_output_are_rejected() {
    for args in [
        vec!["apkeep"],
        vec!["apkeep", "-a", "com.example.app"],
        vec!["apkeep", "-c", "apps.csv"],
        vec!["apkeep", "-a", "com.example.app", "-c", "apps.csv", "-l"],
    ] {
        assert!(app().try_get_matches_from(args).is_err());
    }
    assert!(app()
        .try_get_matches_from(["apkeep", "-c", "apps.csv", "-l"])
        .is_ok());
}

#[test]
fn token_types_conflict_but_oauth_token_can_omit_app_and_outpath() {
    assert!(app()
        .try_get_matches_from([
            "apkeep",
            "-a",
            "com.example.app",
            "-l",
            "-t",
            "fixture-aas",
            "--auth-token",
            "fixture-auth",
        ])
        .is_err());
    let matches = app()
        .try_get_matches_from([
            "apkeep",
            "--oauth-token",
            "fixture-oauth",
            "-e",
            "fixture@example.invalid",
        ])
        .unwrap();
    assert!(matches.get_one::<String>("app").is_none());
    assert!(matches.get_one::<String>("OUTPATH").is_none());
    assert_eq!(
        matches.get_one::<String>("google_oauth_token").unwrap(),
        "fixture-oauth"
    );
}

#[test]
fn numeric_arguments_reject_negative_overflow_and_non_numeric_values() {
    for flag in ["-r", "-s", "-f", "-v"] {
        for value in ["-1", "invalid", "18446744073709551616000000000"] {
            assert!(
                app()
                    .try_get_matches_from(["apkeep", "-c", "apps.csv", "-l", flag, value,])
                    .is_err(),
                "flag {flag}"
            );
        }
    }
}

#[test]
fn generated_usage_matches_rendered_help_exactly() {
    assert_eq!(
        app().render_help().to_string().as_bytes(),
        include_bytes!("../USAGE")
    );
}
