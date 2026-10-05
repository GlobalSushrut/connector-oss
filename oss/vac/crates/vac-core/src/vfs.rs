//! Virtual Filesystem (VFS) — POSIX-like filesystem abstraction for Connector
//!
//! This module implements a virtual filesystem with:
//! - Standard directory structure (/m/, /k/, /v/, /x/, /c/, /a/, /t/, /s/, /p/)
//! - Path-based addressing for all resources
//! - Mount table for namespace composition
//! - Inode-like metadata for all objects
//! - Standard syscalls (open, read, write, close, stat, readdir)
//!
//! Design sources: POSIX.1-2017, Plan 9 namespaces, Linux VFS layer

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

// =============================================================================
// Path Types
// =============================================================================

/// Absolute path in the VFS
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VfsPath(String);

impl VfsPath {
    /// Create a new path (must be absolute)
    pub fn new(path: impl Into<String>) -> Result<Self, VfsError> {
        let path = path.into();
        if !path.starts_with('/') {
            return Err(VfsError::InvalidPath("Path must be absolute".to_string()));
        }
        Ok(Self(Self::normalize(&path)))
    }

    /// Create root path
    pub fn root() -> Self {
        Self("/".to_string())
    }

    /// Normalize a path (remove .., ., trailing slashes, etc.)
    fn normalize(path: &str) -> String {
        let mut components: Vec<&str> = vec![];
        for part in path.split('/') {
            match part {
                "" | "." => continue,
                ".." => { components.pop(); }
                _ => components.push(part),
            }
        }
        if components.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    /// Get the path as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get parent directory
    pub fn parent(&self) -> Option<Self> {
        if self.0 == "/" {
            return None;
        }
        let idx = self.0.rfind('/')?;
        if idx == 0 {
            Some(Self("/".to_string()))
        } else {
            Some(Self(self.0[..idx].to_string()))
        }
    }

    /// Get filename (last component)
    pub fn filename(&self) -> &str {
        if self.0 == "/" {
            return "/";
        }
        self.0.rsplit('/').next().unwrap_or("")
    }

    /// Join with another path component
    pub fn join(&self, name: &str) -> Self {
        if self.0 == "/" {
            Self(format!("/{}", name))
        } else {
            Self(format!("{}/{}", self.0, name))
        }
    }

    /// Check if this path is a child of another
    pub fn is_child_of(&self, parent: &Self) -> bool {
        if parent.0 == "/" {
            self.0.len() > 1
        } else {
            self.0.starts_with(&parent.0) && self.0.len() > parent.0.len()
        }
    }

    /// Get the namespace prefix (/m/, /k/, etc.)
    pub fn namespace_prefix(&self) -> Option<&str> {
        if self.0.len() < 2 {
            return None;
        }
        let parts: Vec<&str> = self.0.splitn(3, '/').collect();
        if parts.len() >= 2 && !parts[1].is_empty() {
            Some(parts[1])
        } else {
            None
        }
    }

    /// Get components as iterator
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// Get depth (number of components)
    pub fn depth(&self) -> usize {
        self.components().count()
    }
}

impl std::fmt::Display for VfsPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for VfsPath {
    fn from(s: &str) -> Self {
        Self::new(s).unwrap_or_else(|_| Self::root())
    }
}

// =============================================================================
// Inode Types
// =============================================================================

/// Inode number
pub type Ino = u64;

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    /// Regular file (memory packet, config, etc.)
    Regular,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Named pipe (FIFO)
    Fifo,
    /// Socket
    Socket,
    /// Block device
    BlockDevice,
    /// Character device
    CharDevice,
    /// Agent (special type)
    Agent,
    /// Session (special type)
    Session,
    /// Port (special type)
    Port,
    /// Tool (special type)
    Tool,
}

impl FileType {
    pub fn mode_bits(&self) -> u32 {
        match self {
            Self::Regular => 0o100000,
            Self::Directory => 0o040000,
            Self::Symlink => 0o120000,
            Self::Fifo => 0o010000,
            Self::Socket => 0o140000,
            Self::BlockDevice => 0o060000,
            Self::CharDevice => 0o020000,
            Self::Agent => 0o100000,
            Self::Session => 0o100000,
            Self::Port => 0o140000,
            Self::Tool => 0o100000,
        }
    }

    pub fn char(&self) -> char {
        match self {
            Self::Regular => '-',
            Self::Directory => 'd',
            Self::Symlink => 'l',
            Self::Fifo => 'p',
            Self::Socket => 's',
            Self::BlockDevice => 'b',
            Self::CharDevice => 'c',
            Self::Agent => 'a',
            Self::Session => 'S',
            Self::Port => 'P',
            Self::Tool => 't',
        }
    }
}

/// File permissions (Unix-style)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FileMode(pub u32);

impl FileMode {
    pub const S_IRWXU: u32 = 0o700;
    pub const S_IRUSR: u32 = 0o400;
    pub const S_IWUSR: u32 = 0o200;
    pub const S_IXUSR: u32 = 0o100;
    pub const S_IRWXG: u32 = 0o070;
    pub const S_IRGRP: u32 = 0o040;
    pub const S_IWGRP: u32 = 0o020;
    pub const S_IXGRP: u32 = 0o010;
    pub const S_IRWXO: u32 = 0o007;
    pub const S_IROTH: u32 = 0o004;
    pub const S_IWOTH: u32 = 0o002;
    pub const S_IXOTH: u32 = 0o001;

    pub fn new(mode: u32) -> Self {
        Self(mode & 0o7777)
    }

    pub fn default_file() -> Self {
        Self(0o644)
    }

    pub fn default_dir() -> Self {
        Self(0o755)
    }

    pub fn can_read(&self, is_owner: bool, is_group: bool) -> bool {
        if is_owner {
            self.0 & Self::S_IRUSR != 0
        } else if is_group {
            self.0 & Self::S_IRGRP != 0
        } else {
            self.0 & Self::S_IROTH != 0
        }
    }

    pub fn can_write(&self, is_owner: bool, is_group: bool) -> bool {
        if is_owner {
            self.0 & Self::S_IWUSR != 0
        } else if is_group {
            self.0 & Self::S_IWGRP != 0
        } else {
            self.0 & Self::S_IWOTH != 0
        }
    }

    pub fn can_execute(&self, is_owner: bool, is_group: bool) -> bool {
        if is_owner {
            self.0 & Self::S_IXUSR != 0
        } else if is_group {
            self.0 & Self::S_IXGRP != 0
        } else {
            self.0 & Self::S_IXOTH != 0
        }
    }

    pub fn to_string(&self) -> String {
        let mut s = String::with_capacity(9);
        s.push(if self.0 & Self::S_IRUSR != 0 { 'r' } else { '-' });
        s.push(if self.0 & Self::S_IWUSR != 0 { 'w' } else { '-' });
        s.push(if self.0 & Self::S_IXUSR != 0 { 'x' } else { '-' });
        s.push(if self.0 & Self::S_IRGRP != 0 { 'r' } else { '-' });
        s.push(if self.0 & Self::S_IWGRP != 0 { 'w' } else { '-' });
        s.push(if self.0 & Self::S_IXGRP != 0 { 'x' } else { '-' });
        s.push(if self.0 & Self::S_IROTH != 0 { 'r' } else { '-' });
        s.push(if self.0 & Self::S_IWOTH != 0 { 'w' } else { '-' });
        s.push(if self.0 & Self::S_IXOTH != 0 { 'x' } else { '-' });
        s
    }
}

impl Default for FileMode {
    fn default() -> Self {
        Self::default_file()
    }
}

/// Inode — metadata for a filesystem object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inode {
    /// Inode number
    pub ino: Ino,
    /// File type
    pub file_type: FileType,
    /// Permissions
    pub mode: FileMode,
    /// Number of hard links
    pub nlink: u32,
    /// Owner user ID
    pub uid: String,
    /// Owner group ID
    pub gid: String,
    /// Size in bytes
    pub size: u64,
    /// Block size
    pub blksize: u32,
    /// Number of blocks
    pub blocks: u64,
    /// Access time (epoch ms)
    pub atime: i64,
    /// Modification time (epoch ms)
    pub mtime: i64,
    /// Change time (epoch ms)
    pub ctime: i64,
    /// Birth time (epoch ms)
    pub btime: i64,
    /// Content ID (CID) for content-addressed storage
    pub cid: Option<String>,
    /// Extended attributes
    pub xattrs: HashMap<String, Vec<u8>>,
}

impl Inode {
    pub fn new(ino: Ino, file_type: FileType) -> Self {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            ino,
            file_type,
            mode: if file_type == FileType::Directory {
                FileMode::default_dir()
            } else {
                FileMode::default_file()
            },
            nlink: 1,
            uid: "root".to_string(),
            gid: "root".to_string(),
            size: 0,
            blksize: 4096,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            btime: now,
            cid: None,
            xattrs: HashMap::new(),
        }
    }

    pub fn touch(&mut self) {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.atime = now;
        self.mtime = now;
        self.ctime = now;
    }

    pub fn update_size(&mut self, size: u64) {
        self.size = size;
        self.blocks = (size + self.blksize as u64 - 1) / self.blksize as u64;
    }
}

// =============================================================================
// Directory Entry
// =============================================================================

/// Directory entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Entry name
    pub name: String,
    /// Inode number
    pub ino: Ino,
    /// File type (cached from inode)
    pub file_type: FileType,
}

impl DirEntry {
    pub fn new(name: String, ino: Ino, file_type: FileType) -> Self {
        Self { name, ino, file_type }
    }
}

// =============================================================================
// Mount Table
// =============================================================================

/// Mount point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountPoint {
    /// Mount path
    pub path: VfsPath,
    /// Source (device, remote, etc.)
    pub source: String,
    /// Filesystem type
    pub fstype: String,
    /// Mount options
    pub options: Vec<String>,
    /// Read-only flag
    pub readonly: bool,
    /// Mount time
    pub mount_time: i64,
}

impl MountPoint {
    pub fn new(path: VfsPath, source: String, fstype: String) -> Self {
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            path,
            source,
            fstype,
            options: vec![],
            readonly: false,
            mount_time: now,
        }
    }
}

/// Mount table
#[derive(Debug, Default)]
pub struct MountTable {
    mounts: Vec<MountPoint>,
}

impl MountTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with standard Connector mounts
    pub fn with_standard_mounts() -> Self {
        let mut table = Self::new();
        
        // Standard namespace mounts
        table.mount(MountPoint::new(
            VfsPath::new("/m").unwrap(),
            "memory".to_string(),
            "memfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/k").unwrap(),
            "knowledge".to_string(),
            "knowledgefs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/v").unwrap(),
            "assets".to_string(),
            "assetfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/x").unwrap(),
            "apps".to_string(),
            "appfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/c").unwrap(),
            "core".to_string(),
            "corefs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/a").unwrap(),
            "agents".to_string(),
            "procfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/t").unwrap(),
            "tools".to_string(),
            "tmpfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/s").unwrap(),
            "system".to_string(),
            "sysfs".to_string(),
        ));
        table.mount(MountPoint::new(
            VfsPath::new("/p").unwrap(),
            "public".to_string(),
            "pubfs".to_string(),
        ));

        table
    }

    pub fn mount(&mut self, mount: MountPoint) {
        // Remove existing mount at same path
        self.mounts.retain(|m| m.path != mount.path);
        self.mounts.push(mount);
    }

    pub fn umount(&mut self, path: &VfsPath) -> bool {
        let len = self.mounts.len();
        self.mounts.retain(|m| &m.path != path);
        self.mounts.len() < len
    }

    pub fn find(&self, path: &VfsPath) -> Option<&MountPoint> {
        // Find the most specific mount point
        self.mounts.iter()
            .filter(|m| path.as_str().starts_with(m.path.as_str()))
            .max_by_key(|m| m.path.depth())
    }

    pub fn list(&self) -> &[MountPoint] {
        &self.mounts
    }
}

// =============================================================================
// VFS Error
// =============================================================================

/// VFS error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VfsError {
    /// File not found
    NotFound(String),
    /// Permission denied
    PermissionDenied(String),
    /// File exists
    Exists(String),
    /// Not a directory
    NotDirectory(String),
    /// Is a directory
    IsDirectory(String),
    /// Invalid path
    InvalidPath(String),
    /// No space left
    NoSpace(String),
    /// Read-only filesystem
    ReadOnly(String),
    /// Too many open files
    TooManyOpen(String),
    /// Invalid argument
    InvalidArgument(String),
    /// I/O error
    IoError(String),
    /// Cross-device link
    CrossDevice(String),
    /// Directory not empty
    NotEmpty(String),
    /// Name too long
    NameTooLong(String),
    /// Loop detected
    Loop(String),
}

impl std::fmt::Display for VfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) => write!(f, "ENOENT: {}", s),
            Self::PermissionDenied(s) => write!(f, "EACCES: {}", s),
            Self::Exists(s) => write!(f, "EEXIST: {}", s),
            Self::NotDirectory(s) => write!(f, "ENOTDIR: {}", s),
            Self::IsDirectory(s) => write!(f, "EISDIR: {}", s),
            Self::InvalidPath(s) => write!(f, "EINVAL: {}", s),
            Self::NoSpace(s) => write!(f, "ENOSPC: {}", s),
            Self::ReadOnly(s) => write!(f, "EROFS: {}", s),
            Self::TooManyOpen(s) => write!(f, "EMFILE: {}", s),
            Self::InvalidArgument(s) => write!(f, "EINVAL: {}", s),
            Self::IoError(s) => write!(f, "EIO: {}", s),
            Self::CrossDevice(s) => write!(f, "EXDEV: {}", s),
            Self::NotEmpty(s) => write!(f, "ENOTEMPTY: {}", s),
            Self::NameTooLong(s) => write!(f, "ENAMETOOLONG: {}", s),
            Self::Loop(s) => write!(f, "ELOOP: {}", s),
        }
    }
}

impl std::error::Error for VfsError {}

pub type VfsResult<T> = Result<T, VfsError>;

// =============================================================================
// Open Flags
// =============================================================================

/// File open flags
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    /// Read access
    pub read: bool,
    /// Write access
    pub write: bool,
    /// Create if not exists
    pub create: bool,
    /// Fail if exists (with create)
    pub excl: bool,
    /// Truncate to zero length
    pub trunc: bool,
    /// Append mode
    pub append: bool,
    /// Non-blocking I/O
    pub nonblock: bool,
    /// Close on exec
    pub cloexec: bool,
    /// Directory only
    pub directory: bool,
    /// No follow symlinks
    pub nofollow: bool,
}

impl OpenFlags {
    pub const O_RDONLY: u32 = 0o0;
    pub const O_WRONLY: u32 = 0o1;
    pub const O_RDWR: u32 = 0o2;
    pub const O_CREAT: u32 = 0o100;
    pub const O_EXCL: u32 = 0o200;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_NONBLOCK: u32 = 0o4000;
    pub const O_CLOEXEC: u32 = 0o2000000;
    pub const O_DIRECTORY: u32 = 0o200000;
    pub const O_NOFOLLOW: u32 = 0o400000;

    pub fn from_bits(flags: u32) -> Self {
        let access = flags & 0o3;
        Self {
            read: access == Self::O_RDONLY || access == Self::O_RDWR,
            write: access == Self::O_WRONLY || access == Self::O_RDWR,
            create: flags & Self::O_CREAT != 0,
            excl: flags & Self::O_EXCL != 0,
            trunc: flags & Self::O_TRUNC != 0,
            append: flags & Self::O_APPEND != 0,
            nonblock: flags & Self::O_NONBLOCK != 0,
            cloexec: flags & Self::O_CLOEXEC != 0,
            directory: flags & Self::O_DIRECTORY != 0,
            nofollow: flags & Self::O_NOFOLLOW != 0,
        }
    }

    pub fn read_only() -> Self {
        Self { read: true, ..Default::default() }
    }

    pub fn write_only() -> Self {
        Self { write: true, ..Default::default() }
    }

    pub fn read_write() -> Self {
        Self { read: true, write: true, ..Default::default() }
    }

    pub fn create_write() -> Self {
        Self { write: true, create: true, ..Default::default() }
    }
}

// =============================================================================
// Virtual Filesystem
// =============================================================================

/// Virtual Filesystem — manages all filesystem operations
#[derive(Debug)]
pub struct Vfs {
    /// Inode table
    inodes: HashMap<Ino, Inode>,
    /// Path to inode mapping
    path_to_ino: HashMap<VfsPath, Ino>,
    /// Directory contents (ino -> entries)
    directories: HashMap<Ino, Vec<DirEntry>>,
    /// File contents (ino -> data)
    file_data: HashMap<Ino, Vec<u8>>,
    /// Symlink targets
    symlinks: HashMap<Ino, VfsPath>,
    /// Mount table
    mounts: MountTable,
    /// Next inode number
    next_ino: Ino,
}

impl Default for Vfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs {
    pub fn new() -> Self {
        let mut vfs = Self {
            inodes: HashMap::new(),
            path_to_ino: HashMap::new(),
            directories: HashMap::new(),
            file_data: HashMap::new(),
            symlinks: HashMap::new(),
            mounts: MountTable::with_standard_mounts(),
            next_ino: 2, // 1 is reserved for root
        };

        // Create root directory
        let root_ino = 1;
        let root_inode = Inode::new(root_ino, FileType::Directory);
        vfs.inodes.insert(root_ino, root_inode);
        vfs.path_to_ino.insert(VfsPath::root(), root_ino);
        vfs.directories.insert(root_ino, vec![]);

        // Create standard directories
        let standard_dirs = [
            "/m",  // Memory (agent working data)
            "/k",  // Knowledge (shared knowledge bases)
            "/v",  // Assets (raw input files)
            "/x",  // Apps (MCP protocol)
            "/c",  // Core (native tools, CNP)
            "/a",  // Agents (control plane)
            "/t",  // Tools (ephemeral I/O)
            "/s",  // System (kernel-reserved)
            "/p",  // Public (announcements)
        ];

        for dir in standard_dirs {
            let _ = vfs.mkdir(&VfsPath::new(dir).unwrap(), FileMode::default_dir());
        }

        vfs
    }

    /// Allocate a new inode number
    fn alloc_ino(&mut self) -> Ino {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    /// Get inode by path
    pub fn lookup(&self, path: &VfsPath) -> VfsResult<&Inode> {
        let ino = self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        self.inodes.get(ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))
    }

    /// Get mutable inode by path
    pub fn lookup_mut(&mut self, path: &VfsPath) -> VfsResult<&mut Inode> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        self.inodes.get_mut(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))
    }

    /// Stat a file (get inode info)
    pub fn stat(&self, path: &VfsPath) -> VfsResult<Inode> {
        self.lookup(path).cloned()
    }

    /// Create a directory
    pub fn mkdir(&mut self, path: &VfsPath, mode: FileMode) -> VfsResult<Ino> {
        // Check if already exists
        if self.path_to_ino.contains_key(path) {
            return Err(VfsError::Exists(path.to_string()));
        }

        // Check parent exists and is a directory
        let parent = path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot create root".to_string()))?;
        let parent_ino = *self.path_to_ino.get(&parent)
            .ok_or_else(|| VfsError::NotFound(parent.to_string()))?;
        let parent_inode = self.inodes.get(&parent_ino)
            .ok_or_else(|| VfsError::NotFound(parent.to_string()))?;
        if parent_inode.file_type != FileType::Directory {
            return Err(VfsError::NotDirectory(parent.to_string()));
        }

        // Create new directory
        let ino = self.alloc_ino();
        let mut inode = Inode::new(ino, FileType::Directory);
        inode.mode = mode;

        self.inodes.insert(ino, inode);
        self.path_to_ino.insert(path.clone(), ino);
        self.directories.insert(ino, vec![]);

        // Add entry to parent
        let entry = DirEntry::new(path.filename().to_string(), ino, FileType::Directory);
        self.directories.get_mut(&parent_ino).unwrap().push(entry);

        // Update parent link count
        if let Some(parent_inode) = self.inodes.get_mut(&parent_ino) {
            parent_inode.nlink += 1;
        }

        Ok(ino)
    }

    /// Create a file
    pub fn create(&mut self, path: &VfsPath, mode: FileMode, file_type: FileType) -> VfsResult<Ino> {
        // Check if already exists
        if self.path_to_ino.contains_key(path) {
            return Err(VfsError::Exists(path.to_string()));
        }

        // Check parent exists and is a directory
        let parent = path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot create root".to_string()))?;
        let parent_ino = *self.path_to_ino.get(&parent)
            .ok_or_else(|| VfsError::NotFound(parent.to_string()))?;

        // Create new file
        let ino = self.alloc_ino();
        let mut inode = Inode::new(ino, file_type);
        inode.mode = mode;

        self.inodes.insert(ino, inode);
        self.path_to_ino.insert(path.clone(), ino);
        self.file_data.insert(ino, vec![]);

        // Add entry to parent
        let entry = DirEntry::new(path.filename().to_string(), ino, file_type);
        self.directories.get_mut(&parent_ino).unwrap().push(entry);

        Ok(ino)
    }

    /// Read directory contents
    pub fn readdir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type != FileType::Directory {
            return Err(VfsError::NotDirectory(path.to_string()));
        }

        let entries = self.directories.get(&ino)
            .cloned()
            .unwrap_or_default();
        Ok(entries)
    }

    /// Write data to a file
    pub fn write(&mut self, path: &VfsPath, data: &[u8], offset: u64) -> VfsResult<usize> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsDirectory(path.to_string()));
        }

        let file_data = self.file_data.entry(ino).or_insert_with(Vec::new);
        let offset = offset as usize;
        
        // Extend file if needed
        if offset + data.len() > file_data.len() {
            file_data.resize(offset + data.len(), 0);
        }
        
        file_data[offset..offset + data.len()].copy_from_slice(data);

        // Update inode
        if let Some(inode) = self.inodes.get_mut(&ino) {
            inode.update_size(file_data.len() as u64);
            inode.touch();
        }

        Ok(data.len())
    }

    /// Read data from a file
    pub fn read(&self, path: &VfsPath, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsDirectory(path.to_string()));
        }

        let file_data = self.file_data.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        let offset = offset as usize;
        if offset >= file_data.len() {
            return Ok(0);
        }

        let to_read = buf.len().min(file_data.len() - offset);
        buf[..to_read].copy_from_slice(&file_data[offset..offset + to_read]);

        Ok(to_read)
    }

    /// Remove a file
    pub fn unlink(&mut self, path: &VfsPath) -> VfsResult<()> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type == FileType::Directory {
            return Err(VfsError::IsDirectory(path.to_string()));
        }

        // Remove from parent
        let parent = path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot unlink root".to_string()))?;
        let parent_ino = *self.path_to_ino.get(&parent)
            .ok_or_else(|| VfsError::NotFound(parent.to_string()))?;
        
        if let Some(entries) = self.directories.get_mut(&parent_ino) {
            entries.retain(|e| e.ino != ino);
        }

        // Remove inode and data
        self.inodes.remove(&ino);
        self.path_to_ino.remove(path);
        self.file_data.remove(&ino);

        Ok(())
    }

    /// Remove a directory
    pub fn rmdir(&mut self, path: &VfsPath) -> VfsResult<()> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type != FileType::Directory {
            return Err(VfsError::NotDirectory(path.to_string()));
        }

        // Check if empty
        if let Some(entries) = self.directories.get(&ino) {
            if !entries.is_empty() {
                return Err(VfsError::NotEmpty(path.to_string()));
            }
        }

        // Remove from parent
        let parent = path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot rmdir root".to_string()))?;
        let parent_ino = *self.path_to_ino.get(&parent)
            .ok_or_else(|| VfsError::NotFound(parent.to_string()))?;
        
        if let Some(entries) = self.directories.get_mut(&parent_ino) {
            entries.retain(|e| e.ino != ino);
        }

        // Update parent link count
        if let Some(parent_inode) = self.inodes.get_mut(&parent_ino) {
            parent_inode.nlink = parent_inode.nlink.saturating_sub(1);
        }

        // Remove inode
        self.inodes.remove(&ino);
        self.path_to_ino.remove(path);
        self.directories.remove(&ino);

        Ok(())
    }

    /// Rename/move a file or directory
    pub fn rename(&mut self, old_path: &VfsPath, new_path: &VfsPath) -> VfsResult<()> {
        let ino = *self.path_to_ino.get(old_path)
            .ok_or_else(|| VfsError::NotFound(old_path.to_string()))?;

        // Remove from old parent
        let old_parent = old_path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot rename root".to_string()))?;
        let old_parent_ino = *self.path_to_ino.get(&old_parent)
            .ok_or_else(|| VfsError::NotFound(old_parent.to_string()))?;
        
        if let Some(entries) = self.directories.get_mut(&old_parent_ino) {
            entries.retain(|e| e.ino != ino);
        }

        // Add to new parent
        let new_parent = new_path.parent()
            .ok_or_else(|| VfsError::InvalidPath("Cannot rename to root".to_string()))?;
        let new_parent_ino = *self.path_to_ino.get(&new_parent)
            .ok_or_else(|| VfsError::NotFound(new_parent.to_string()))?;
        
        let file_type = self.inodes.get(&ino)
            .map(|i| i.file_type)
            .unwrap_or(FileType::Regular);
        
        let entry = DirEntry::new(new_path.filename().to_string(), ino, file_type);
        self.directories.get_mut(&new_parent_ino)
            .ok_or_else(|| VfsError::NotDirectory(new_parent.to_string()))?
            .push(entry);

        // Update path mapping
        self.path_to_ino.remove(old_path);
        self.path_to_ino.insert(new_path.clone(), ino);

        // Update ctime
        if let Some(inode) = self.inodes.get_mut(&ino) {
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            inode.ctime = now;
        }

        Ok(())
    }

    /// Create a symbolic link
    pub fn symlink(&mut self, target: &VfsPath, link_path: &VfsPath) -> VfsResult<Ino> {
        let ino = self.create(link_path, FileMode::new(0o777), FileType::Symlink)?;
        self.symlinks.insert(ino, target.clone());
        Ok(ino)
    }

    /// Read a symbolic link
    pub fn readlink(&self, path: &VfsPath) -> VfsResult<VfsPath> {
        let ino = *self.path_to_ino.get(path)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        let inode = self.inodes.get(&ino)
            .ok_or_else(|| VfsError::NotFound(path.to_string()))?;
        
        if inode.file_type != FileType::Symlink {
            return Err(VfsError::InvalidArgument("Not a symlink".to_string()));
        }

        self.symlinks.get(&ino)
            .cloned()
            .ok_or_else(|| VfsError::NotFound(path.to_string()))
    }

    /// Get mount table
    pub fn mounts(&self) -> &MountTable {
        &self.mounts
    }

    /// Get mutable mount table
    pub fn mounts_mut(&mut self) -> &mut MountTable {
        &mut self.mounts
    }

    /// Check if path exists
    pub fn exists(&self, path: &VfsPath) -> bool {
        self.path_to_ino.contains_key(path)
    }

    /// Check if path is a directory
    pub fn is_dir(&self, path: &VfsPath) -> bool {
        self.lookup(path)
            .map(|i| i.file_type == FileType::Directory)
            .unwrap_or(false)
    }

    /// Check if path is a file
    pub fn is_file(&self, path: &VfsPath) -> bool {
        self.lookup(path)
            .map(|i| i.file_type == FileType::Regular)
            .unwrap_or(false)
    }

    /// Walk directory tree
    pub fn walk(&self, root: &VfsPath) -> Vec<(VfsPath, Inode)> {
        let mut result = vec![];
        self.walk_recursive(root, &mut result);
        result
    }

    fn walk_recursive(&self, path: &VfsPath, result: &mut Vec<(VfsPath, Inode)>) {
        if let Ok(inode) = self.lookup(path) {
            result.push((path.clone(), inode.clone()));
            
            if inode.file_type == FileType::Directory {
                if let Ok(entries) = self.readdir(path) {
                    for entry in entries {
                        let child_path = path.join(&entry.name);
                        self.walk_recursive(&child_path, result);
                    }
                }
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vfs_path() {
        let path = VfsPath::new("/m/agent1/session").unwrap();
        assert_eq!(path.as_str(), "/m/agent1/session");
        assert_eq!(path.filename(), "session");
        assert_eq!(path.parent().unwrap().as_str(), "/m/agent1");
        assert_eq!(path.namespace_prefix(), Some("m"));
        assert_eq!(path.depth(), 3);
    }

    #[test]
    fn test_vfs_mkdir() {
        let mut vfs = Vfs::new();
        
        // Standard dirs already exist
        assert!(vfs.exists(&VfsPath::new("/m").unwrap()));
        
        // Create nested dir
        let ino = vfs.mkdir(&VfsPath::new("/m/agent1").unwrap(), FileMode::default_dir()).unwrap();
        assert!(ino > 0);
        assert!(vfs.is_dir(&VfsPath::new("/m/agent1").unwrap()));
    }

    #[test]
    fn test_vfs_file_ops() {
        let mut vfs = Vfs::new();
        
        let path = VfsPath::new("/m/test.txt").unwrap();
        vfs.create(&path, FileMode::default_file(), FileType::Regular).unwrap();
        
        // Write
        let data = b"Hello, World!";
        let written = vfs.write(&path, data, 0).unwrap();
        assert_eq!(written, 13);
        
        // Read
        let mut buf = [0u8; 20];
        let read = vfs.read(&path, &mut buf, 0).unwrap();
        assert_eq!(read, 13);
        assert_eq!(&buf[..13], data);
        
        // Stat
        let inode = vfs.stat(&path).unwrap();
        assert_eq!(inode.size, 13);
    }

    #[test]
    fn test_vfs_readdir() {
        let mut vfs = Vfs::new();
        
        vfs.create(&VfsPath::new("/m/file1.txt").unwrap(), FileMode::default_file(), FileType::Regular).unwrap();
        vfs.create(&VfsPath::new("/m/file2.txt").unwrap(), FileMode::default_file(), FileType::Regular).unwrap();
        vfs.mkdir(&VfsPath::new("/m/subdir").unwrap(), FileMode::default_dir()).unwrap();
        
        let entries = vfs.readdir(&VfsPath::new("/m").unwrap()).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn test_mount_table() {
        let table = MountTable::with_standard_mounts();
        
        let mount = table.find(&VfsPath::new("/m/agent1/session").unwrap()).unwrap();
        assert_eq!(mount.path.as_str(), "/m");
        assert_eq!(mount.fstype, "memfs");
    }
}
