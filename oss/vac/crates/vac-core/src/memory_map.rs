//! Memory Map Inspection — /proc/<pid>/maps equivalent
//!
//! This module implements memory map inspection for agents:
//! - Memory regions with permissions (read/write/execute)
//! - Address space layout (heap, stack, mmap regions)
//! - Memory protection and access tracking
//! - Shared memory regions between agents
//! - Memory statistics and usage reporting
//!
//! Design sources: Linux /proc/<pid>/maps, mmap(), shmget()

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::process::Pid;

// =============================================================================
// Memory Region Types
// =============================================================================

/// Memory region ID
pub type RegionId = String;

/// Generate a new region ID
static REGION_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn generate_region_id(pid: &str) -> RegionId {
    let id = REGION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{}:region:{:08x}", pid, id)
}

/// Memory protection flags (like mprotect)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProtection {
    /// Readable
    pub read: bool,
    /// Writable
    pub write: bool,
    /// Executable
    pub execute: bool,
    /// Shared (vs private/copy-on-write)
    pub shared: bool,
}

impl MemoryProtection {
    pub const NONE: Self = Self { read: false, write: false, execute: false, shared: false };
    pub const READ: Self = Self { read: true, write: false, execute: false, shared: false };
    pub const READ_WRITE: Self = Self { read: true, write: true, execute: false, shared: false };
    pub const READ_EXEC: Self = Self { read: true, write: false, execute: true, shared: false };
    pub const READ_WRITE_EXEC: Self = Self { read: true, write: true, execute: true, shared: false };
    pub const SHARED_READ: Self = Self { read: true, write: false, execute: false, shared: true };
    pub const SHARED_READ_WRITE: Self = Self { read: true, write: true, execute: false, shared: true };

    /// Parse from string like "rwxs" or "r-x-"
    pub fn from_str(s: &str) -> Self {
        let chars: Vec<char> = s.chars().collect();
        Self {
            read: chars.first() == Some(&'r'),
            write: chars.get(1) == Some(&'w'),
            execute: chars.get(2) == Some(&'x'),
            shared: chars.get(3) == Some(&'s'),
        }
    }

    /// Format as string like "rwxs" or "r-x-"
    pub fn to_string(&self) -> String {
        format!(
            "{}{}{}{}",
            if self.read { 'r' } else { '-' },
            if self.write { 'w' } else { '-' },
            if self.execute { 'x' } else { '-' },
            if self.shared { 's' } else { 'p' },
        )
    }

    /// Check if protection allows read
    pub fn can_read(&self) -> bool {
        self.read
    }

    /// Check if protection allows write
    pub fn can_write(&self) -> bool {
        self.write
    }

    /// Check if protection allows execute
    pub fn can_execute(&self) -> bool {
        self.execute
    }
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self::READ_WRITE
    }
}

/// Memory region type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionType {
    /// Code/text segment
    Code,
    /// Data segment (initialized)
    Data,
    /// BSS segment (uninitialized)
    Bss,
    /// Heap (dynamic allocation)
    Heap,
    /// Stack
    Stack,
    /// Memory-mapped file
    MappedFile,
    /// Anonymous mapping (mmap without file)
    Anonymous,
    /// Shared memory region
    Shared,
    /// Guard page (no access)
    Guard,
    /// Reserved (not yet allocated)
    Reserved,
}

impl Default for RegionType {
    fn default() -> Self {
        Self::Anonymous
    }
}

// =============================================================================
// Memory Region
// =============================================================================

/// Memory region — a contiguous range of virtual memory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    /// Region ID
    pub id: RegionId,
    /// Owner agent PID
    pub owner_pid: Pid,
    /// Start address (virtual)
    pub start_addr: u64,
    /// End address (virtual)
    pub end_addr: u64,
    /// Size in bytes
    pub size: u64,
    /// Protection flags
    pub protection: MemoryProtection,
    /// Region type
    pub region_type: RegionType,
    /// Offset in backing file (if mapped)
    pub file_offset: u64,
    /// Backing file path (if mapped)
    pub file_path: Option<String>,
    /// Backing CID (if content-addressed)
    pub backing_cid: Option<String>,
    /// Name/label for this region
    pub name: Option<String>,
    /// Resident set size (bytes actually in memory)
    pub rss: u64,
    /// Private dirty pages (bytes)
    pub private_dirty: u64,
    /// Shared dirty pages (bytes)
    pub shared_dirty: u64,
    /// Private clean pages (bytes)
    pub private_clean: u64,
    /// Shared clean pages (bytes)
    pub shared_clean: u64,
    /// Swap usage (bytes)
    pub swap: u64,
    /// Page faults (minor)
    pub minor_faults: u64,
    /// Page faults (major)
    pub major_faults: u64,
    /// Created timestamp (epoch ms)
    pub created_at: i64,
    /// Last accessed timestamp (epoch ms)
    pub last_accessed_at: Option<i64>,
    /// Locked in memory (mlock)
    pub locked: bool,
    /// Huge pages enabled
    pub huge_pages: bool,
}

impl MemoryRegion {
    /// Create a new memory region
    pub fn new(
        owner_pid: Pid,
        start_addr: u64,
        size: u64,
        protection: MemoryProtection,
        region_type: RegionType,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: generate_region_id(&owner_pid),
            owner_pid,
            start_addr,
            end_addr: start_addr + size,
            size,
            protection,
            region_type,
            file_offset: 0,
            file_path: None,
            backing_cid: None,
            name: None,
            rss: 0,
            private_dirty: 0,
            shared_dirty: 0,
            private_clean: 0,
            shared_clean: 0,
            swap: 0,
            minor_faults: 0,
            major_faults: 0,
            created_at: now,
            last_accessed_at: None,
            locked: false,
            huge_pages: false,
        }
    }

    /// Create a heap region
    pub fn heap(owner_pid: Pid, start_addr: u64, size: u64) -> Self {
        let mut region = Self::new(owner_pid, start_addr, size, MemoryProtection::READ_WRITE, RegionType::Heap);
        region.name = Some("[heap]".to_string());
        region
    }

    /// Create a stack region
    pub fn stack(owner_pid: Pid, start_addr: u64, size: u64) -> Self {
        let mut region = Self::new(owner_pid, start_addr, size, MemoryProtection::READ_WRITE, RegionType::Stack);
        region.name = Some("[stack]".to_string());
        region
    }

    /// Create a code region
    pub fn code(owner_pid: Pid, start_addr: u64, size: u64, file_path: Option<String>) -> Self {
        let mut region = Self::new(owner_pid, start_addr, size, MemoryProtection::READ_EXEC, RegionType::Code);
        region.file_path = file_path;
        region
    }

    /// Create a shared memory region
    pub fn shared(owner_pid: Pid, start_addr: u64, size: u64, name: String) -> Self {
        let mut region = Self::new(owner_pid, start_addr, size, MemoryProtection::SHARED_READ_WRITE, RegionType::Shared);
        region.name = Some(name);
        region
    }

    /// Create a memory-mapped file region
    pub fn mapped_file(owner_pid: Pid, start_addr: u64, size: u64, file_path: String, offset: u64, writable: bool) -> Self {
        let prot = if writable { MemoryProtection::READ_WRITE } else { MemoryProtection::READ };
        let mut region = Self::new(owner_pid, start_addr, size, prot, RegionType::MappedFile);
        region.file_path = Some(file_path);
        region.file_offset = offset;
        region
    }

    /// Check if address is within this region
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }

    /// Check if regions overlap
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.start_addr < other.end_addr && other.start_addr < self.end_addr
    }

    /// Change protection
    pub fn mprotect(&mut self, protection: MemoryProtection) {
        self.protection = protection;
    }

    /// Lock region in memory
    pub fn mlock(&mut self) {
        self.locked = true;
    }

    /// Unlock region
    pub fn munlock(&mut self) {
        self.locked = false;
    }

    /// Record access
    pub fn record_access(&mut self) {
        self.last_accessed_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64
        );
    }

    /// Record page fault
    pub fn record_fault(&mut self, major: bool) {
        if major {
            self.major_faults += 1;
        } else {
            self.minor_faults += 1;
        }
    }

    /// Format as /proc/<pid>/maps line
    pub fn to_maps_line(&self) -> String {
        let file = self.file_path.as_deref()
            .or(self.name.as_deref())
            .unwrap_or("");
        
        format!(
            "{:016x}-{:016x} {} {:08x} 00:00 0 {}",
            self.start_addr,
            self.end_addr,
            self.protection.to_string(),
            self.file_offset,
            file
        )
    }
}

// =============================================================================
// Memory Map
// =============================================================================

/// Memory map — all regions for an agent (like /proc/<pid>/maps)
#[derive(Debug, Default)]
pub struct MemoryMap {
    /// Owner agent PID
    pid: Pid,
    /// Regions by ID
    regions: HashMap<RegionId, MemoryRegion>,
    /// Regions sorted by start address (for fast lookup)
    sorted_addrs: Vec<(u64, RegionId)>,
    /// Next available address for allocation
    next_addr: u64,
    /// Total virtual size
    total_virtual: u64,
    /// Total resident size
    total_rss: u64,
    /// Address space limits
    limits: AddressSpaceLimits,
}

/// Address space limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressSpaceLimits {
    /// Maximum virtual memory (bytes)
    pub max_virtual: u64,
    /// Maximum resident memory (bytes)
    pub max_rss: u64,
    /// Maximum regions
    pub max_regions: usize,
    /// Maximum locked memory (bytes)
    pub max_locked: u64,
}

impl Default for AddressSpaceLimits {
    fn default() -> Self {
        Self {
            max_virtual: 8 * 1024 * 1024 * 1024, // 8GB
            max_rss: 2 * 1024 * 1024 * 1024,     // 2GB
            max_regions: 65536,
            max_locked: 64 * 1024 * 1024,        // 64MB
        }
    }
}

impl MemoryMap {
    /// Create a new memory map for an agent
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            regions: HashMap::new(),
            sorted_addrs: vec![],
            next_addr: 0x1000, // Start after null page
            total_virtual: 0,
            total_rss: 0,
            limits: AddressSpaceLimits::default(),
        }
    }

    /// Create with standard regions (heap, stack)
    pub fn with_standard_layout(pid: Pid, heap_size: u64, stack_size: u64) -> Self {
        let mut map = Self::new(pid.clone());
        
        // Heap at low address
        let heap = MemoryRegion::heap(pid.clone(), 0x10000, heap_size);
        map.add_region(heap);

        // Stack at high address (grows down)
        let stack_start = 0x7fff_0000_0000 - stack_size;
        let stack = MemoryRegion::stack(pid, stack_start, stack_size);
        map.add_region(stack);

        map
    }

    /// Add a region
    pub fn add_region(&mut self, region: MemoryRegion) -> Result<RegionId, String> {
        // Check limits
        if self.regions.len() >= self.limits.max_regions {
            return Err("Too many regions".to_string());
        }
        if self.total_virtual + region.size > self.limits.max_virtual {
            return Err("Virtual memory limit exceeded".to_string());
        }

        // Check for overlaps
        for existing in self.regions.values() {
            if region.overlaps(existing) {
                return Err(format!("Region overlaps with {}", existing.id));
            }
        }

        let id = region.id.clone();
        self.total_virtual += region.size;
        self.sorted_addrs.push((region.start_addr, id.clone()));
        self.sorted_addrs.sort_by_key(|(addr, _)| *addr);
        self.regions.insert(id.clone(), region);

        Ok(id)
    }

    /// Remove a region (munmap)
    pub fn remove_region(&mut self, id: &str) -> Option<MemoryRegion> {
        if let Some(region) = self.regions.remove(id) {
            self.total_virtual -= region.size;
            self.total_rss -= region.rss;
            self.sorted_addrs.retain(|(_, rid)| rid != id);
            Some(region)
        } else {
            None
        }
    }

    /// Get region by ID
    pub fn get_region(&self, id: &str) -> Option<&MemoryRegion> {
        self.regions.get(id)
    }

    /// Get mutable region by ID
    pub fn get_region_mut(&mut self, id: &str) -> Option<&mut MemoryRegion> {
        self.regions.get_mut(id)
    }

    /// Find region containing address
    pub fn find_by_addr(&self, addr: u64) -> Option<&MemoryRegion> {
        // Binary search in sorted addresses
        let idx = self.sorted_addrs.partition_point(|(a, _)| *a <= addr);
        if idx > 0 {
            let (_, id) = &self.sorted_addrs[idx - 1];
            if let Some(region) = self.regions.get(id) {
                if region.contains(addr) {
                    return Some(region);
                }
            }
        }
        None
    }

    /// Find region by name
    pub fn find_by_name(&self, name: &str) -> Option<&MemoryRegion> {
        self.regions.values().find(|r| r.name.as_deref() == Some(name))
    }

    /// Allocate a new region (mmap)
    pub fn mmap(
        &mut self,
        size: u64,
        protection: MemoryProtection,
        region_type: RegionType,
    ) -> Result<RegionId, String> {
        // Find a free address
        let addr = self.find_free_addr(size)?;
        let region = MemoryRegion::new(self.pid.clone(), addr, size, protection, region_type);
        self.add_region(region)
    }

    /// Find a free address for allocation
    fn find_free_addr(&mut self, size: u64) -> Result<u64, String> {
        // Simple bump allocator
        let addr = self.next_addr;
        self.next_addr += size;
        
        // Align to page boundary
        self.next_addr = (self.next_addr + 0xfff) & !0xfff;
        
        Ok(addr)
    }

    /// Change protection on a region
    pub fn mprotect(&mut self, id: &str, protection: MemoryProtection) -> Result<(), String> {
        if let Some(region) = self.regions.get_mut(id) {
            region.mprotect(protection);
            Ok(())
        } else {
            Err("Region not found".to_string())
        }
    }

    /// List all regions
    pub fn list_regions(&self) -> Vec<&MemoryRegion> {
        let mut regions: Vec<_> = self.regions.values().collect();
        regions.sort_by_key(|r| r.start_addr);
        regions
    }

    /// Format as /proc/<pid>/maps
    pub fn to_maps(&self) -> String {
        self.list_regions()
            .iter()
            .map(|r| r.to_maps_line())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get memory statistics
    pub fn stats(&self) -> MemoryMapStats {
        let mut stats = MemoryMapStats::default();
        
        for region in self.regions.values() {
            stats.total_regions += 1;
            stats.total_virtual += region.size;
            stats.total_rss += region.rss;
            stats.total_swap += region.swap;
            stats.private_dirty += region.private_dirty;
            stats.shared_dirty += region.shared_dirty;
            
            if region.locked {
                stats.locked += region.size;
            }
            
            match region.region_type {
                RegionType::Heap => stats.heap_size += region.size,
                RegionType::Stack => stats.stack_size += region.size,
                RegionType::Code => stats.code_size += region.size,
                RegionType::Shared => stats.shared_size += region.size,
                _ => {}
            }
        }
        
        stats
    }

    /// Get PID
    pub fn pid(&self) -> &str {
        &self.pid
    }
}

/// Memory map statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryMapStats {
    pub total_regions: usize,
    pub total_virtual: u64,
    pub total_rss: u64,
    pub total_swap: u64,
    pub private_dirty: u64,
    pub shared_dirty: u64,
    pub locked: u64,
    pub heap_size: u64,
    pub stack_size: u64,
    pub code_size: u64,
    pub shared_size: u64,
}

// =============================================================================
// Shared Memory
// =============================================================================

/// Shared memory segment ID
pub type ShmId = String;

/// Generate a new shared memory ID
static SHM_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn generate_shm_id() -> ShmId {
    let id = SHM_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("shm:{:08x}", id)
}

/// Shared memory segment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMemorySegment {
    /// Segment ID
    pub id: ShmId,
    /// Name/key for lookup
    pub name: String,
    /// Size in bytes
    pub size: u64,
    /// Creator PID
    pub creator_pid: Pid,
    /// Attached processes (pid -> attach info)
    pub attachments: HashMap<Pid, ShmAttachment>,
    /// Protection flags
    pub protection: MemoryProtection,
    /// Created timestamp
    pub created_at: i64,
    /// Last attach timestamp
    pub last_attach_at: Option<i64>,
    /// Last detach timestamp
    pub last_detach_at: Option<i64>,
    /// Number of current attachments
    pub nattach: usize,
    /// Marked for deletion
    pub marked_for_deletion: bool,
    /// Backing CID (content-addressed storage)
    pub backing_cid: Option<String>,
}

/// Shared memory attachment info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShmAttachment {
    /// Attached PID
    pub pid: Pid,
    /// Virtual address in attacher's space
    pub addr: u64,
    /// Read-only attachment
    pub readonly: bool,
    /// Attach timestamp
    pub attached_at: i64,
}

impl SharedMemorySegment {
    /// Create a new shared memory segment
    pub fn new(name: String, size: u64, creator_pid: Pid) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            id: generate_shm_id(),
            name,
            size,
            creator_pid,
            attachments: HashMap::new(),
            protection: MemoryProtection::SHARED_READ_WRITE,
            created_at: now,
            last_attach_at: None,
            last_detach_at: None,
            nattach: 0,
            marked_for_deletion: false,
            backing_cid: None,
        }
    }

    /// Attach to segment
    pub fn attach(&mut self, pid: Pid, addr: u64, readonly: bool) -> Result<(), String> {
        if self.marked_for_deletion {
            return Err("Segment marked for deletion".to_string());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        self.attachments.insert(pid.clone(), ShmAttachment {
            pid,
            addr,
            readonly,
            attached_at: now,
        });
        self.nattach = self.attachments.len();
        self.last_attach_at = Some(now);

        Ok(())
    }

    /// Detach from segment
    pub fn detach(&mut self, pid: &str) -> Result<(), String> {
        if self.attachments.remove(pid).is_some() {
            self.nattach = self.attachments.len();
            self.last_detach_at = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64
            );
            Ok(())
        } else {
            Err("Not attached".to_string())
        }
    }

    /// Mark for deletion (will be deleted when nattach == 0)
    pub fn mark_for_deletion(&mut self) {
        self.marked_for_deletion = true;
    }

    /// Check if should be deleted
    pub fn should_delete(&self) -> bool {
        self.marked_for_deletion && self.nattach == 0
    }

    /// Check if PID is attached
    pub fn is_attached(&self, pid: &str) -> bool {
        self.attachments.contains_key(pid)
    }
}

/// Shared memory manager
#[derive(Debug, Default)]
pub struct SharedMemoryManager {
    /// Segments by ID
    segments: HashMap<ShmId, SharedMemorySegment>,
    /// Segments by name
    by_name: HashMap<String, ShmId>,
    /// Total shared memory size
    total_size: u64,
    /// Limits
    limits: SharedMemoryLimits,
}

/// Shared memory limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMemoryLimits {
    /// Maximum total shared memory
    pub max_total: u64,
    /// Maximum segments
    pub max_segments: usize,
    /// Maximum segment size
    pub max_segment_size: u64,
    /// Maximum attachments per segment
    pub max_attachments: usize,
}

impl Default for SharedMemoryLimits {
    fn default() -> Self {
        Self {
            max_total: 4 * 1024 * 1024 * 1024, // 4GB
            max_segments: 4096,
            max_segment_size: 1024 * 1024 * 1024, // 1GB
            max_attachments: 256,
        }
    }
}

impl SharedMemoryManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a shared memory segment (shmget)
    pub fn shmget(&mut self, name: String, size: u64, creator_pid: Pid) -> Result<ShmId, String> {
        // Check if already exists
        if let Some(id) = self.by_name.get(&name) {
            return Ok(id.clone());
        }

        // Check limits
        if self.segments.len() >= self.limits.max_segments {
            return Err("Too many segments".to_string());
        }
        if size > self.limits.max_segment_size {
            return Err("Segment too large".to_string());
        }
        if self.total_size + size > self.limits.max_total {
            return Err("Total shared memory limit exceeded".to_string());
        }

        let segment = SharedMemorySegment::new(name.clone(), size, creator_pid);
        let id = segment.id.clone();
        
        self.total_size += size;
        self.by_name.insert(name, id.clone());
        self.segments.insert(id.clone(), segment);

        Ok(id)
    }

    /// Attach to shared memory (shmat)
    pub fn shmat(&mut self, id: &str, pid: Pid, addr: u64, readonly: bool) -> Result<(), String> {
        let segment = self.segments.get_mut(id).ok_or("Segment not found")?;
        
        if segment.attachments.len() >= self.limits.max_attachments {
            return Err("Too many attachments".to_string());
        }

        segment.attach(pid, addr, readonly)
    }

    /// Detach from shared memory (shmdt)
    pub fn shmdt(&mut self, id: &str, pid: &str) -> Result<(), String> {
        let segment = self.segments.get_mut(id).ok_or("Segment not found")?;
        segment.detach(pid)?;

        // Clean up if marked for deletion and no attachments
        if segment.should_delete() {
            self.remove_segment(id);
        }

        Ok(())
    }

    /// Mark segment for deletion (shmctl IPC_RMID)
    pub fn shmctl_rmid(&mut self, id: &str) -> Result<(), String> {
        let segment = self.segments.get_mut(id).ok_or("Segment not found")?;
        segment.mark_for_deletion();

        if segment.should_delete() {
            self.remove_segment(id);
        }

        Ok(())
    }

    /// Remove segment
    fn remove_segment(&mut self, id: &str) {
        if let Some(segment) = self.segments.remove(id) {
            self.total_size -= segment.size;
            self.by_name.remove(&segment.name);
        }
    }

    /// Get segment by ID
    pub fn get(&self, id: &str) -> Option<&SharedMemorySegment> {
        self.segments.get(id)
    }

    /// Get segment by name
    pub fn get_by_name(&self, name: &str) -> Option<&SharedMemorySegment> {
        self.by_name.get(name).and_then(|id| self.segments.get(id))
    }

    /// List all segments
    pub fn list(&self) -> Vec<&SharedMemorySegment> {
        self.segments.values().collect()
    }

    /// List segments attached by PID
    pub fn list_by_pid(&self, pid: &str) -> Vec<&SharedMemorySegment> {
        self.segments.values()
            .filter(|s| s.is_attached(pid))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> SharedMemoryStats {
        SharedMemoryStats {
            total_segments: self.segments.len(),
            total_size: self.total_size,
            total_attachments: self.segments.values().map(|s| s.nattach).sum(),
        }
    }
}

/// Shared memory statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedMemoryStats {
    pub total_segments: usize,
    pub total_size: u64,
    pub total_attachments: usize,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_protection() {
        let prot = MemoryProtection::READ_WRITE;
        assert!(prot.can_read());
        assert!(prot.can_write());
        assert!(!prot.can_execute());
        assert_eq!(prot.to_string(), "rw-p");

        let prot = MemoryProtection::from_str("r-xp");
        assert!(prot.can_read());
        assert!(!prot.can_write());
        assert!(prot.can_execute());
    }

    #[test]
    fn test_memory_region() {
        let region = MemoryRegion::heap("pid:001".to_string(), 0x10000, 0x100000);
        
        assert_eq!(region.region_type, RegionType::Heap);
        assert!(region.contains(0x10000));
        assert!(region.contains(0x50000));
        assert!(!region.contains(0x110000));
    }

    #[test]
    fn test_memory_map() {
        let mut map = MemoryMap::with_standard_layout("pid:001".to_string(), 0x100000, 0x10000);
        
        let stats = map.stats();
        assert_eq!(stats.total_regions, 2);
        assert!(stats.heap_size > 0);
        assert!(stats.stack_size > 0);

        // Add anonymous region
        let id = map.mmap(0x1000, MemoryProtection::READ_WRITE, RegionType::Anonymous).unwrap();
        assert!(map.get_region(&id).is_some());

        // Find by address
        let heap = map.find_by_name("[heap]").unwrap();
        let found = map.find_by_addr(heap.start_addr + 100).unwrap();
        assert_eq!(found.id, heap.id);
    }

    #[test]
    fn test_maps_output() {
        let mut map = MemoryMap::new("pid:001".to_string());
        
        let heap = MemoryRegion::heap("pid:001".to_string(), 0x10000, 0x100000);
        map.add_region(heap).unwrap();

        let maps = map.to_maps();
        assert!(maps.contains("[heap]"));
        assert!(maps.contains("rw-p"));
    }

    #[test]
    fn test_shared_memory() {
        let mut shm = SharedMemoryManager::new();

        // Create segment
        let id = shm.shmget("test_shm".to_string(), 0x10000, "pid:001".to_string()).unwrap();

        // Attach
        shm.shmat(&id, "pid:001".to_string(), 0x20000, false).unwrap();
        shm.shmat(&id, "pid:002".to_string(), 0x30000, true).unwrap();

        let segment = shm.get(&id).unwrap();
        assert_eq!(segment.nattach, 2);
        assert!(segment.is_attached("pid:001"));
        assert!(segment.is_attached("pid:002"));

        // Detach
        shm.shmdt(&id, "pid:001").unwrap();
        let segment = shm.get(&id).unwrap();
        assert_eq!(segment.nattach, 1);

        // Mark for deletion
        shm.shmctl_rmid(&id).unwrap();
        assert!(shm.get(&id).is_some()); // Still exists (pid:002 attached)

        shm.shmdt(&id, "pid:002").unwrap();
        assert!(shm.get(&id).is_none()); // Now deleted
    }

    #[test]
    fn test_shared_memory_by_name() {
        let mut shm = SharedMemoryManager::new();

        let id1 = shm.shmget("my_shm".to_string(), 0x1000, "pid:001".to_string()).unwrap();
        
        let segment = shm.get_by_name("my_shm").unwrap();
        assert_eq!(segment.name, "my_shm");

        // Getting same name returns same segment
        let id2 = shm.shmget("my_shm".to_string(), 0x2000, "pid:002".to_string()).unwrap();
        assert_eq!(id2, id1);
    }
}
