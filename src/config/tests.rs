use super::*;
use std::os::unix::fs::symlink;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "nwtop-config-test-{}-{sequence}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn config(&self) -> ConfigFile {
        ConfigFile::at(self.0.join("nwtop/config.json"))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn legacy_settings_migrate_on_save_with_unknown_keys_preserved() {
    let directory = TestDirectory::new();
    let legacy = ConfigFile::at(directory.0.join("nettop/config.json"));
    legacy.save(&Settings::default()).unwrap();
    let original = br#"{"bits":true,"future_option":{"kept":true}}"#;
    fs::write(legacy.path(), original).unwrap();
    let config = ConfigFile {
        path: directory.config().path,
        legacy_path: Some(legacy.path.clone()),
    };
    let loaded = config.load_with_unknown_keys().unwrap();
    assert!(loaded.settings.bits);
    assert_eq!(loaded.unknown_keys, ["future_option"]);
    assert!(!config.path().exists());
    config.save(&loaded.settings).unwrap();
    assert_eq!(config.load_with_unknown_keys().unwrap(), loaded);
    assert_eq!(fs::read(legacy.path()).unwrap(), original);
    assert_eq!(fs::metadata(config.path()).unwrap().mode() & 0o777, 0o600);
    let saved: Value = serde_json::from_slice(&fs::read(config.path()).unwrap()).unwrap();
    assert_eq!(saved["future_option"]["kept"], true);
    // Once migrated, the new file wins even if the old one becomes invalid.
    fs::write(legacy.path(), "invalid").unwrap();
    assert_eq!(config.load_with_unknown_keys().unwrap(), loaded);
    config.save(&loaded.settings).unwrap();
}

#[test]
fn malformed_primary_settings_do_not_fall_back_to_legacy() {
    let directory = TestDirectory::new();
    let legacy = ConfigFile::at(directory.0.join("nettop/config.json"));
    legacy.save(&Settings::default()).unwrap();
    let mut config = directory.config();
    config.save(&Settings::default()).unwrap();
    config.legacy_path = Some(legacy.path);
    fs::write(config.path(), "invalid").unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
    assert_eq!(fs::read_to_string(config.path()).unwrap(), "invalid");
}

#[test]
fn invalid_or_symlinked_legacy_settings_do_not_migrate() {
    let directory = TestDirectory::new();
    let legacy = ConfigFile::at(directory.0.join("nettop/config.json"));
    legacy.save(&Settings::default()).unwrap();
    let config = ConfigFile {
        path: directory.config().path,
        legacy_path: Some(legacy.path.clone()),
    };
    fs::write(legacy.path(), "invalid").unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
    assert!(!config.path().exists());
    assert_eq!(fs::read_to_string(legacy.path()).unwrap(), "invalid");
    fs::remove_file(legacy.path()).unwrap();
    let target = directory.0.join("target.json");
    fs::write(&target, "{}").unwrap();
    symlink(&target, legacy.path()).unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
    assert!(!config.path().exists());
    assert_eq!(fs::read_to_string(target).unwrap(), "{}");
}

#[test]
fn missing_settings_default_and_roundtrip_updates_are_private() {
    let directory = TestDirectory::new();
    let config = directory.config();
    assert_eq!(config.load().unwrap(), Settings::default());
    assert!(!config.path().exists());
    let mut expected = Settings {
        interface: Some("all".to_owned()),
        bits: true,
        rx_color: PlotColor::Magenta,
        ..Settings::default()
    };
    config.save(&expected).unwrap();
    assert_eq!(config.load().unwrap(), expected);
    assert_eq!(fs::metadata(config.path()).unwrap().mode() & 0o777, 0o600);
    expected.interval_ms = 250;
    config.save(&expected).unwrap();
    assert_eq!(config.load().unwrap(), expected);
    assert_eq!(
        fs::read_dir(config.path().parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn missing_fields_use_defaults_and_invalid_settings_are_preserved() {
    let directory = TestDirectory::new();
    let config = directory.config();
    config.save(&Settings::default()).unwrap();
    fs::write(config.path(), br#"{"bits": true}"#).unwrap();
    assert_eq!(
        config.load().unwrap(),
        Settings {
            bits: true,
            ..Settings::default()
        }
    );
    for bytes in [
        "this is not settings JSON".to_owned(),
        r#"{"interval_ms":99}"#.to_owned(),
        r#"{"interval_ms":60001}"#.to_owned(),
        r#"{"history_seconds":9}"#.to_owned(),
        r#"{"history_seconds":601}"#.to_owned(),
        r#"{"version":2}"#.to_owned(),
        r#"{"interface":"../x"}"#.to_owned(),
        r#"{"interface":"a\u0000b"}"#.to_owned(),
        r#"{"interface":"1234567890123456"}"#.to_owned(),
        r#"{"graph_style":"unknown"}"#.to_owned(),
        "x".repeat(MAX_BYTES as usize + 1),
    ] {
        fs::write(config.path(), &bytes).unwrap();
        assert!(config.load().is_err());
        assert!(config.save(&Settings::default()).is_err());
        assert_eq!(fs::read_to_string(config.path()).unwrap(), bytes);
    }
}

#[test]
fn file_symlinks_hardlinks_and_unsafe_files_are_never_overwritten() {
    let directory = TestDirectory::new();
    let config = directory.config();
    DirBuilder::new()
        .mode(0o700)
        .create(config.path().parent().unwrap())
        .unwrap();
    let target = directory.0.join("unrelated");
    fs::write(&target, "precious data").unwrap();
    symlink(&target, config.path()).unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
    assert!(config.path().is_symlink());
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious data");
    fs::remove_file(config.path()).unwrap();
    fs::hard_link(&target, config.path()).unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "precious data");
    fs::remove_file(config.path()).unwrap();
    config.save(&Settings::default()).unwrap();
    fs::set_permissions(config.path(), fs::Permissions::from_mode(0o666)).unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
}

#[test]
fn safe_symlinked_directories_work_but_shared_directories_do_not() {
    let directory = TestDirectory::new();
    let actual = directory.0.join("actual");
    DirBuilder::new().mode(0o700).create(&actual).unwrap();
    let alias = directory.0.join("alias");
    symlink(&actual, &alias).unwrap();
    let config = ConfigFile::at(alias.join("config.json"));
    config.save(&Settings::default()).unwrap();
    assert_eq!(config.load().unwrap(), Settings::default());
    fs::set_permissions(&actual, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
}

#[test]
fn special_files_are_rejected_without_waiting_for_a_writer() {
    let directory = TestDirectory::new();
    let config = directory.config();
    DirBuilder::new()
        .mode(0o700)
        .create(config.path().parent().unwrap())
        .unwrap();
    let name = CString::new(config.path().as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a valid C string in our owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(config.load().is_err());
    assert!(config.save(&Settings::default()).is_err());
}

#[test]
fn unknown_keys_are_reported_and_preserved_when_saving() {
    let directory = TestDirectory::new();
    let config = directory.config();
    config.save(&Settings::default()).unwrap();
    fs::write(
        config.path(),
        br#"{"bits": true, "colour": false, "future": {"nested": [1, 2]}}"#,
    )
    .unwrap();
    let loaded = config.load_with_unknown_keys().unwrap();
    assert!(loaded.settings.bits);
    assert_eq!(loaded.unknown_keys, ["colour", "future"]);
    let changed = Settings {
        history_seconds: 120,
        ..loaded.settings
    };
    config.save(&changed).unwrap();
    let saved: Value = serde_json::from_slice(&fs::read(config.path()).unwrap()).unwrap();
    assert_eq!(saved["colour"], Value::Bool(false));
    assert_eq!(saved["future"]["nested"][1], 2);
    assert_eq!(saved["history_seconds"], 120);
    let reloaded = config.load_with_unknown_keys().unwrap();
    assert_eq!(reloaded.settings, changed);
    assert_eq!(reloaded.unknown_keys, ["colour", "future"]);
    // Known preferences always come from the saved settings, never extras.
    assert_eq!(saved["version"], 1);
}

#[test]
fn language_defaults_to_auto_and_older_files_stay_compatible() {
    let directory = TestDirectory::new();
    let config = directory.config();
    config.save(&Settings::default()).unwrap();
    fs::write(config.path(), br#"{"version": 1, "bits": true}"#).unwrap();
    assert_eq!(config.load().unwrap().language, Language::Auto);
    fs::write(config.path(), br#"{"version": 1, "language": "de"}"#).unwrap();
    assert_eq!(config.load().unwrap().language, Language::De);
    fs::write(config.path(), br#"{"version": 1, "language": "fr"}"#).unwrap();
    assert!(config.load().is_err());
    assert_eq!(Language::Auto.next(1), Language::En);
    assert_eq!(Language::Auto.next(-1), Language::De);
}

#[test]
fn root_refuses_settings_below_another_users_directory() {
    let directory = TestDirectory::new();
    let nested = directory.0.join("missing/nwtop");
    // Ordinary users are never affected by the root-only refusal.
    assert!(refuse_foreign_directory_as_root(&nested, 1000).is_ok());
    let owner = fs::metadata(&directory.0).unwrap().uid();
    let result = refuse_foreign_directory_as_root(&nested, 0);
    if owner == 0 {
        assert!(result.is_ok());
    } else {
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<RootWithForeignSettings>().is_some());
        assert!(error.to_string().contains("without sudo"));
        assert!(
            !nested.exists(),
            "refusal must happen before creating directories"
        );
    }
}

#[test]
fn differing_fields_copy_only_selected_preferences() {
    let saved = Settings {
        interface: Some("eth0".into()),
        ..Settings::default()
    };
    let runtime = Settings {
        interface: None,
        bits: true,
        color: false,
        language: Language::De,
        ..saved.clone()
    };
    assert_eq!(
        runtime.differing(&saved),
        [Field::Interface, Field::Bits, Field::Color, Field::Language]
    );
    let mut merged = saved.clone();
    merged.copy_field(&runtime, Field::Bits);
    assert!(merged.bits);
    assert!(merged.color);
    assert_eq!(merged.interface.as_deref(), Some("eth0"));
    assert_eq!(merged.differing(&saved), [Field::Bits]);
}

#[test]
fn setting_choices_cycle_in_both_directions() {
    assert_eq!(PlotColor::Green.next(-1), PlotColor::White);
    assert_eq!(PlotColor::White.next(1), PlotColor::Green);
    assert_eq!(GraphStyle::Steps.next(-1), GraphStyle::Braille);
    assert_eq!(GraphStyle::Braille.next(1), GraphStyle::Steps);
    assert_eq!(PlotColor::Green.next(0), PlotColor::Green);
}
