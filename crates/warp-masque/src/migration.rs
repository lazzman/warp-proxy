//! 从 MicroWARP 的 instances/<编号>/masque-config.json 导入已有账号身份。

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::pool::{account_path, remember_saved_temporary, saved_account_ids};
use crate::{Error, Result, WarpConfig};

const MIGRATION_FILE: &str = "microwarp-migrations.json";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Default, Serialize, Deserialize)]
struct MigrationManifest {
    entries: Vec<MigrationEntry>,
}

#[derive(Serialize, Deserialize)]
struct MigrationEntry {
    source: String,
    device_id: String,
    account_id: usize,
}

/// 扫描 MicroWARP 目录。已导入的身份不会再次复制，原始文件始终只读。
pub fn migrate_microwarp(state_dir: &Path, source_dir: &Path, base_count: usize) -> Result<usize> {
    migrate_excluding(state_dir, source_dir, base_count, &[])
}

pub(crate) fn migrate_excluding(
    state_dir: &Path,
    source_dir: &Path,
    base_count: usize,
    reserved: &[usize],
) -> Result<usize> {
    let instances = if source_dir.join("instances").is_dir() {
        source_dir.join("instances")
    } else {
        source_dir.to_path_buf()
    };
    let entries = match fs::read_dir(&instances) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(err.into()),
    };
    let mut sources = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<usize>().ok())
        {
            sources.push((number, entry.path()));
        }
    }
    sources.sort_by_key(|(number, _)| *number);
    if sources.is_empty() {
        return Ok(0);
    }

    fs::create_dir_all(state_dir)?;
    let manifest_path = state_dir.join(MIGRATION_FILE);
    let mut manifest: MigrationManifest = match fs::read(&manifest_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
            Error::Config(format!(
                "无法读取迁移记录 {}: {err}",
                manifest_path.display()
            ))
        })?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => MigrationManifest::default(),
        Err(err) => return Err(err.into()),
    };

    let mut occupied: HashSet<usize> = reserved.iter().copied().collect();
    let mut by_device = HashMap::new();
    for id in saved_account_ids(state_dir) {
        occupied.insert(id);
        if let Ok(config) = WarpConfig::load(account_path(state_dir, id)) {
            by_device.entry(config.id).or_insert(id);
        }
    }
    let mut imported = 0;
    for (number, dir) in sources {
        let source_path = dir.join("masque-config.json");
        if !source_path.is_file() {
            continue;
        }
        let config = match WarpConfig::load(&source_path) {
            Ok(config) if !config.id.trim().is_empty() && !config.private_key.trim().is_empty() => {
                config
            }
            Ok(_) => {
                eprintln!(
                    "[migration] 跳过缺少设备身份的配置 {}",
                    source_path.display()
                );
                continue;
            }
            Err(err) => {
                eprintln!("[migration] 暂时无法读取 {}: {err}", source_path.display());
                continue;
            }
        };
        let source = dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if manifest
            .entries
            .iter()
            .any(|entry| entry.source == source && entry.device_id == config.id)
        {
            continue;
        }

        let account_id = if let Some(&id) = by_device.get(&config.id) {
            id
        } else {
            let id = (1..)
                .find(|id| !occupied.contains(id))
                .ok_or_else(|| Error::Config("没有可用的账号编号".into()))?;
            save_new_config(&config, &account_path(state_dir, id))?;
            occupied.insert(id);
            by_device.insert(config.id.clone(), id);
            imported += 1;
            id
        };
        if account_id > base_count {
            remember_saved_temporary(state_dir, account_id)?;
        }
        manifest.entries.push(MigrationEntry {
            source,
            device_id: config.id,
            account_id,
        });
        write_json_atomic(&manifest_path, &manifest)?;
        eprintln!("[migration] MicroWARP 实例 {number} 已迁移为账号 {account_id}，记录迁移完成");
    }
    Ok(imported)
}

fn save_new_config(config: &WarpConfig, path: &Path) -> Result<()> {
    let json = serde_json::to_vec_pretty(config)?;
    let tmp = temporary_path(path);
    write_new_file(&tmp, &json)?;
    let result = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match result {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Err(err.into()),
        Err(_) => write_new_file(path, &json),
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(err.into());
    }
    Ok(())
}

pub(crate) fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_vec_pretty(value)?;
    let tmp = temporary_path(path);
    write_new_file(&tmp, &json)?;
    let result = fs::rename(&tmp, path);
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Error::from)
}

fn temporary_path(path: &Path) -> std::path::PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(
        ".{}.{}.{sequence}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::read_temporary_active;

    fn fixture() -> std::path::PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("warp-microwarp-{}-{sequence}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn source(dir: &Path, slot: usize, device: &str) {
        let path = dir.join("instances").join(slot.to_string());
        fs::create_dir_all(&path).unwrap();
        WarpConfig {
            id: device.into(),
            private_key: format!("key-{device}"),
            endpoint_v4: "162.159.198.1".into(),
            endpoint_v6: "2606:4700:103::1".into(),
            endpoint_pub_key: "pubkey".into(),
            access_token: "token".into(),
            ipv4: "172.16.0.2".into(),
            ipv6: "2606:4700:110::1".into(),
            ..Default::default()
        }
        .save(path.join("masque-config.json"))
        .unwrap();
    }

    #[test]
    fn migrates_new_instances_and_records_completion() {
        let dir = fixture();
        let state = dir.join("state");
        source(&dir, 0, "device-0");
        source(&dir, 1, "device-1");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 2);
        assert_eq!(
            WarpConfig::load(account_path(&state, 1)).unwrap().id,
            "device-0"
        );
        assert_eq!(
            WarpConfig::load(account_path(&state, 2)).unwrap().id,
            "device-1"
        );
        assert_eq!(read_temporary_active(&state).unwrap(), vec![2]);
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        let record: MigrationManifest =
            serde_json::from_slice(&fs::read(state.join(MIGRATION_FILE)).unwrap()).unwrap();
        assert_eq!(record.entries.len(), 2);
        assert_eq!(record.entries[1].account_id, 2);
        fs::write(state.join("temporary.json"), r#"{"active":[]}"#).unwrap();
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        assert!(read_temporary_active(&state).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn never_overwrites_existing_accounts_and_deduplicates_identity() {
        let dir = fixture();
        let state = dir.join("state");
        fs::create_dir_all(&state).unwrap();
        WarpConfig {
            id: "existing".into(),
            private_key: "safe".into(),
            ..Default::default()
        }
        .save(account_path(&state, 1))
        .unwrap();
        source(&dir, 0, "device-0");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 1);
        assert_eq!(
            WarpConfig::load(account_path(&state, 1)).unwrap().id,
            "existing"
        );
        source(&dir, 1, "device-0");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        source(&dir, 2, "device-2");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 1);
        assert_eq!(read_temporary_active(&state).unwrap(), vec![2, 3]);
        assert_eq!(
            WarpConfig::load(account_path(&state, 3)).unwrap().id,
            "device-2"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_configs_are_retried_without_completion_marker() {
        let dir = fixture();
        let state = dir.join("state");
        let source_dir = dir.join("instances/0");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("masque-config.json"), "{").unwrap();
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        assert!(!state.join(MIGRATION_FILE).exists());
        source(&dir, 0, "fixed");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 1);
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_identity_uses_a_new_slot_without_replacing_previous_account() {
        let dir = fixture();
        let state = dir.join("state");
        source(&dir, 0, "first-device");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 1);
        source(&dir, 0, "second-device");
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 1);
        assert_eq!(
            WarpConfig::load(account_path(&state, 1)).unwrap().id,
            "first-device"
        );
        assert_eq!(
            WarpConfig::load(account_path(&state, 2)).unwrap().id,
            "second-device"
        );
        assert_eq!(read_temporary_active(&state).unwrap(), vec![2]);
        assert_eq!(migrate_microwarp(&state, &dir, 1).unwrap(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_scan_skips_reserved_ids() {
        let dir = fixture();
        let state = dir.join("state");
        source(&dir, 0, "device");
        assert_eq!(migrate_excluding(&state, &dir, 1, &[1]).unwrap(), 1);
        assert!(!account_path(&state, 1).exists());
        assert_eq!(
            WarpConfig::load(account_path(&state, 2)).unwrap().id,
            "device"
        );
        assert_eq!(read_temporary_active(&state).unwrap(), vec![2]);
        fs::remove_dir_all(dir).unwrap();
    }
}
