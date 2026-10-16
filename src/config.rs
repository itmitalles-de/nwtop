//! User-owned UI preferences. The privileged collector never reads this file.

use std::{
    env,
    ffi::{CStr, CString},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

mod settings;

pub use settings::{Field, GraphStyle, Language, PlotColor, Settings, SortKey};

const MAX_BYTES: u64 = 64 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Loaded preferences plus top-level keys that this version does not know.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Loaded {
    pub settings: Settings,
    pub unknown_keys: Vec<String>,
}

/// Saving or loading as root in another user's settings directory, typically
/// after `sudo -E nwtop`, would create root-owned files there.
#[derive(Debug)]
pub struct RootWithForeignSettings;

impl std::fmt::Display for RootWithForeignSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "nwtop runs as root, but the settings directory belongs to another user \
             (for example after sudo -E); start nwtop without sudo to change preferences",
        )
    }
}

impl std::error::Error for RootWithForeignSettings {}

struct Stored {
    settings: Settings,
    extra: Map<String, Value>,
}

#[derive(Serialize)]
struct StoredRef<'a> {
    #[serde(flatten)]
    settings: &'a Settings,
    #[serde(flatten)]
    extra: &'a Map<String, Value>,
}

#[derive(Clone, Debug)]
pub struct ConfigFile {
    path: PathBuf,
    legacy_path: Option<PathBuf>,
}

impl ConfigFile {
    pub fn discover() -> Result<Self> {
        let base = match env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
            // XDG specifies that relative environment paths must be ignored.
            _ => {
                let home =
                    env::var_os("HOME").context("HOME is not set; cannot locate settings")?;
                if !Path::new(&home).is_absolute() {
                    bail!("HOME must be an absolute path to locate settings");
                }
                PathBuf::from(home).join(".config")
            }
        };
        Ok(Self {
            path: base.join("nwtop/config.json"),
            legacy_path: Some(base.join("nettop/config.json")),
        })
    }

    pub fn at(path: PathBuf) -> Self {
        Self {
            path,
            legacy_path: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<Settings> {
        Ok(self.load_with_unknown_keys()?.settings)
    }

    /// Load settings and also report keys this version does not understand.
    /// Unknown keys are kept when saving, so typos and newer options survive F12.
    pub fn load_with_unknown_keys(&self) -> Result<Loaded> {
        self.load_inner().with_context(|| {
            format!(
                "cannot load {}; fix or move this settings file to use defaults",
                self.path.display()
            )
        })
    }

    fn load_inner(&self) -> Result<Loaded> {
        Ok(self
            .read_with_legacy()?
            .map(|stored| Loaded {
                unknown_keys: stored.extra.keys().cloned().collect(),
                settings: stored.settings,
            })
            .unwrap_or_default())
    }

    /// The old name is read only when the new file is absent. Malformed or
    /// unsafe files never silently fall back, and saving always uses nwtop.
    fn read_with_legacy(&self) -> Result<Option<Stored>> {
        match self.read_stored()? {
            Some(stored) => Ok(Some(stored)),
            None => match &self.legacy_path {
                Some(path) => Self::at(path.clone())
                    .read_stored()
                    .with_context(|| format!("cannot read legacy settings {}", path.display())),
                None => Ok(None),
            },
        }
    }

    fn read_stored(&self) -> Result<Option<Stored>> {
        let (parent, name) = self.location()?;
        let directory = match open_directory(parent) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        validate_directory(&directory)?;
        read_settings(&directory, &name)
    }

    pub fn save(&self, settings: &Settings) -> Result<()> {
        settings.validate()?;
        let (parent, _) = self.location()?;
        // SAFETY: geteuid has no preconditions and does not modify process state.
        refuse_foreign_directory_as_root(parent, unsafe { libc::geteuid() })?;
        self.save_inner(settings).with_context(|| {
            format!(
                "cannot save {}; existing settings have not been intentionally discarded",
                self.path.display()
            )
        })
    }

    fn save_inner(&self, settings: &Settings) -> Result<()> {
        let (parent, name) = self.location()?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
        let directory = open_directory(parent)?;
        validate_directory(&directory)?;
        // Never replace an unreadable, malformed, unsupported, or unsafe file.
        let existing = match read_settings(&directory, &name)? {
            Some(stored) => Some(stored),
            None => match &self.legacy_path {
                Some(path) => Self::at(path.clone()).read_stored()?,
                None => None,
            },
        };
        let extra = existing.map(|stored| stored.extra).unwrap_or_default();
        let mut bytes = serde_json::to_vec_pretty(&StoredRef {
            settings,
            extra: &extra,
        })?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_BYTES {
            bail!("serialized settings exceed 64 KiB");
        }
        let (mut file, mut temporary) = TemporaryFile::create(&directory)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // Check again after writing. All operations stay relative to the opened
        // directory, including when a user has symlinked their config directory.
        read_settings(&directory, &name)?;
        // SAFETY: both names are valid C strings and directory stays open.
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temporary.name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        temporary.exists = false;
        directory.sync_all().context("syncing settings directory")?;
        Ok(())
    }

    fn location(&self) -> Result<(&Path, CString)> {
        let name = self
            .path
            .file_name()
            .context("settings path needs a file name")?;
        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        Ok((parent, CString::new(name.as_bytes())?))
    }
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

/// As root, never create or write settings below a directory owned by another
/// user: the result would be root-owned and break that user's normal starts.
fn refuse_foreign_directory_as_root(parent: &Path, euid: libc::uid_t) -> Result<()> {
    if euid != 0 {
        return Ok(());
    }
    // The nearest existing ancestor decides who would own new directories.
    for ancestor in parent.ancestors() {
        let ancestor = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match fs::metadata(ancestor) {
            Ok(metadata) if metadata.uid() != 0 => return Err(RootWithForeignSettings.into()),
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_directory(directory: &File) -> Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions and does not modify process state.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 && metadata.uid() != 0 {
        return Err(RootWithForeignSettings.into());
    }
    if metadata.uid() != euid || metadata.mode() & 0o022 != 0 {
        bail!("settings directory must be user-owned and not writable by other users");
    }
    Ok(())
}

fn read_settings(directory: &File, name: &CStr) -> Result<Option<Stored>> {
    // O_NOFOLLOW rejects the file itself being a symlink; O_NONBLOCK prevents an
    // unsafe FIFO from blocking before its file type can be inspected.
    // SAFETY: name is a valid C string and directory owns an open directory fd.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("opening settings; config.json must not be a symlink");
    }
    // SAFETY: successful openat returned a new fd, now owned only by this File.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions and does not modify process state.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        bail!(
            "settings must be a user-owned regular file without hard links or other write access"
        );
    }
    if metadata.len() > MAX_BYTES {
        bail!("settings file exceeds 64 KiB");
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!("settings file exceeds 64 KiB");
    }
    let value: Value = serde_json::from_slice(&bytes).context("invalid settings JSON")?;
    let settings = Settings::deserialize(&value).context("invalid settings JSON")?;
    settings.validate()?;
    let Value::Object(mut extra) = value else {
        bail!("invalid settings JSON: expected an object");
    };
    let known = serde_json::to_value(Settings::default())?;
    if let Value::Object(known) = known {
        extra.retain(|key, _| !known.contains_key(key));
    }
    Ok(Some(Stored { settings, extra }))
}

struct TemporaryFile<'a> {
    directory: &'a File,
    name: CString,
    exists: bool,
}

impl<'a> TemporaryFile<'a> {
    fn create(directory: &'a File) -> Result<(File, Self)> {
        for _ in 0..100 {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(".nwtop-{}-{sequence}.tmp", std::process::id()))?;
            // SAFETY: name is a valid C string; O_EXCL reserves a new owned file.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600 as libc::mode_t,
                )
            };
            if descriptor >= 0 {
                // SAFETY: this successful openat returned a new, uniquely owned fd.
                let file = unsafe { File::from_raw_fd(descriptor) };
                return Ok((
                    file,
                    Self {
                        directory,
                        name,
                        exists: true,
                    },
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error.into());
            }
        }
        bail!("cannot reserve a temporary settings file");
    }
}

impl Drop for TemporaryFile<'_> {
    fn drop(&mut self) {
        if self.exists {
            // SAFETY: this removes only the temporary name we created; no links
            // are followed and the borrowed directory remains open until return.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

#[cfg(test)]
mod tests;
