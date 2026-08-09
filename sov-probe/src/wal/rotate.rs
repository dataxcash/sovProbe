use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Unlink-Oldest 强制淘汰（评审修正版，替代原「取模覆盖」方案）。
///
/// 段号**单向递增**：segment_0000.wal, segment_0001.wal, ... 永不回写同一文件名。
/// 上限控制：目录内 WAL 数超 max_segments 或总占用超预算时，直接
/// `remove_file` 删除最旧段（Unlink Oldest）。
///
/// 与取模覆盖相比的关键优势（修正致命逻辑死角）：
/// - 文件名全局唯一、单调递增 → slimSync 比对文件名序号即可感知「旧段被抛弃」，
///   不会因同文件 offset 从 64MB 回落到 0 而错乱/崩溃。
/// - 新段是新 inode，fnotify/inotify 触发 IN_CREATE，而非「截断重写」的
///   IN_MODIFY → 下游可明确区分「新段」与「追加」。
/// - RAMDisk 物理占用恒定 ≤ max_segments × segment_size（第一硬红线）。
pub struct Rotator {
    shm_path: PathBuf,
    max_segments: usize,
    seg_no: u64,
    /// 已删除的最旧段号（read_cursor 的物理语义）
    min_no: u64,
}

impl Rotator {
    pub fn new(shm_path: &str, max_segments: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(max_segments >= 1, "max_segments >= 1");
        let path = PathBuf::from(shm_path);
        fs::create_dir_all(&path)?;
        // 重启健壮性：已有 segment_*.wal 时从最大段号+1 续起，绝不复用文件名
        // （段号单调递增契约，避免 create_new 撞现存文件而崩溃）。
        let (seg_no, min_no) = Self::scan_existing(&path);
        Ok(Self {
            shm_path: path,
            max_segments,
            seg_no,
            min_no,
        })
    }

    /// 扫描目录内现有 segment_XXXX.wal，返回 (下一个可用段号, 现存最小段号)。
    fn scan_existing(path: &Path) -> (u64, u64) {
        let mut max = None;
        let mut min = None;
        if let Ok(rd) = fs::read_dir(path) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(stripped) = name
                    .strip_prefix("segment_")
                    .and_then(|s| s.strip_suffix(".wal"))
                {
                    if let Ok(no) = stripped.parse::<u64>() {
                        max = Some(max.map_or(no, |m: u64| m.max(no)));
                        min = Some(min.map_or(no, |m: u64| m.min(no)));
                    }
                }
            }
        }
        (max.map_or(0, |m| m + 1), min.unwrap_or(0))
    }

    /// 段路径：序号直接作为文件名，单向递增，全局唯一。
    fn seg_path(&self, no: u64) -> PathBuf {
        self.shm_path.join(format!("segment_{:04}.wal", no))
    }

    fn ledger_path(&self) -> PathBuf {
        self.shm_path.join("ledger")
    }

    /// 分配下一个写入 segment：新建唯一文件。
    /// 写入前先执行 Unlink-Oldest 淘汰，保证目录体积恒定。
    pub fn next_segment(&mut self) -> anyhow::Result<PathBuf> {
        let no = self.seg_no;
        self.seg_no += 1;
        let path = self.seg_path(no);

        // 创建新段（必然是新 inode，不存在覆盖）
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;

        // Unlink-Oldest：存量段数超限 → 删除最旧段
        self.enforce_budget()?;
        self.persist_ledger(no, None)?;
        Ok(path)
    }

    /// Unlink-Oldest 核心：目录内 WAL 数超 max_segments → 从最旧依次删除。
    /// 删除时同步推进 min_no（read_cursor 语义），并落盘 ledger。
    fn enforce_budget(&mut self) -> anyhow::Result<()> {
        loop {
            let count = self.existing_count();
            if count <= self.max_segments {
                break;
            }
            let oldest = self.seg_path(self.min_no);
            if oldest.exists() {
                fs::remove_file(&oldest)?;
            }
            self.min_no += 1;
            self.persist_ledger(self.seg_no, Some(self.min_no))?;
        }
        Ok(())
    }

    /// slimSync 侧推进 read_cursor 后调用，供覆盖决策参考。
    /// read_cursor 语义：小于等于该序号的 segment 已被消费，可安全淘汰。
    #[allow(dead_code)]
    pub fn mark_read(&self, read_cursor: u64) -> anyhow::Result<()> {
        self.persist_ledger(self.seg_no, Some(read_cursor))
    }

    fn persist_ledger(&self, write_cursor: u64, read_cursor: Option<u64>) -> anyhow::Result<()> {
        let ledger = self.ledger_path();
        let read = match read_cursor {
            Some(r) => r,
            None => {
                if let Ok(s) = fs::read_to_string(&ledger) {
                    let parts: Vec<&str> = s.split_whitespace().collect();
                    if parts.len() >= 2 {
                        parts[1].parse().unwrap_or(write_cursor)
                    } else {
                        write_cursor
                    }
                } else {
                    write_cursor
                }
            }
        };
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&ledger)?;
        writeln!(f, "{} {}", write_cursor, read)?;
        f.sync_all()?;
        Ok(())
    }

    /// 当前物理 segment 文件数。
    pub fn existing_count(&self) -> usize {
        let Ok(rd) = fs::read_dir(&self.shm_path) else {
            return 0;
        };
        rd.filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("segment_"))
            .count()
    }

    /// 当前最小（最旧）存在段号；目录为空时返回 next。
    pub fn min_existing_no(&self) -> u64 {
        let Ok(rd) = fs::read_dir(&self.shm_path) else {
            return self.seg_no;
        };
        let mut min = self.seg_no;
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(stripped) = name.strip_prefix("segment_").and_then(|s| s.strip_suffix(".wal")) {
                if let Ok(no) = stripped.parse::<u64>() {
                    if no < min {
                        min = no;
                    }
                }
            }
        }
        min
    }

    /// 当前已淘汰到的最旧段号（read_cursor）。
    #[allow(dead_code)]
    pub fn min_no(&self) -> u64 {
        self.min_no
    }
}

/// 校验目录是否可写（探针启动自检）。
pub fn check_writable(path: &Path) -> anyhow::Result<()> {
    let probe = path.join(".sovprobe_write_test");
    fs::write(&probe, b"ok")?;
    fs::remove_file(&probe)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_monotonic_unique() {
        let dir = "/tmp/sovprobe_test_mono";
        let _ = fs::remove_dir_all(dir);
        let mut r = Rotator::new(dir, 2).unwrap();
        let s1 = r.next_segment().unwrap();
        let s2 = r.next_segment().unwrap();
        let s3 = r.next_segment().unwrap();
        let s4 = r.next_segment().unwrap();
        assert!(s1.ends_with("segment_0000.wal"));
        assert!(s2.ends_with("segment_0001.wal"));
        assert!(s3.ends_with("segment_0002.wal"));
        assert!(s4.ends_with("segment_0003.wal"));
        // 每个文件名全局唯一
        assert_ne!(s1, s3);
        assert_ne!(s2, s4);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unlink_oldest_keeps_budget() {
        let dir = "/tmp/sovprobe_test_unlink";
        let _ = fs::remove_dir_all(dir);
        let mut r = Rotator::new(dir, 2).unwrap();
        for _ in 0..5 {
            let p = r.next_segment().unwrap();
            fs::write(&p, b"data").unwrap();
        }
        // 物理文件数恒 ≤ 2（Unlink-Oldest）
        assert_eq!(r.existing_count(), 2);
        // 最旧的 0000/0001/0002 已删，现存为 0003/0004
        assert!(r.min_existing_no() >= 3);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_skips_existing_segments() {
        let dir = "/tmp/sovprobe_test_restart";
        let _ = fs::remove_dir_all(dir);
        fs::create_dir_all(dir).unwrap();
        fs::write(format!("{}/segment_0003.wal", dir), b"a").unwrap();
        fs::write(format!("{}/segment_0007.wal", dir), b"b").unwrap();
        let (next, min) = Rotator::scan_existing(Path::new(dir));
        assert_eq!(next, 8, "应从最大段号+1 续起");
        assert_eq!(min, 3, "现存最小段号 3");
        // 完整流程：新分配段号不得撞现存文件
        let mut r = Rotator::new(dir, 8).unwrap();
        let p = r.next_segment().unwrap();
        assert!(p.ends_with("segment_0008.wal"), "新段应跳过已有段号");
        let _ = fs::remove_dir_all(dir);
    }
}
