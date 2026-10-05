//! Hardware Abstraction Layer — DeviceDescriptor, DeviceRegistry, SafetyConstraints.
//!
//! Manages device registration, discovery, heartbeat tracking, and safety enforcement.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::capability::{DeviceClass, InterfaceProtocol};
use crate::error::{CapsError, CapsResult};

/// Safety constraints for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConstraints {
    /// Maximum velocity (for motors/actuators), units depend on device
    pub max_velocity: Option<f64>,
    /// Maximum force in Newtons
    pub max_force: Option<f64>,
    /// Emergency stop always available (cannot be disabled)
    pub emergency_stop: bool,
    /// Watchdog timeout — kill connection if no heartbeat in this many ms
    pub watchdog_timeout_ms: Option<u64>,
    /// Geofence bounding box (min_x, min_y, max_x, max_y)
    pub geofence: Option<(f64, f64, f64, f64)>,
    /// Max operations per second (rate limit)
    pub max_ops_per_second: Option<u32>,
}

impl Default for SafetyConstraints {
    fn default() -> Self {
        Self {
            max_velocity: None,
            max_force: None,
            emergency_stop: true,
            watchdog_timeout_ms: Some(5000),
            geofence: None,
            max_ops_per_second: Some(100),
        }
    }
}

/// Descriptor for a registered hardware device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDescriptor {
    pub device_id: String,
    pub device_class: DeviceClass,
    pub interface: InterfaceProtocol,
    pub capabilities: Vec<String>,
    pub safety: SafetyConstraints,
    pub description: String,
    /// Last heartbeat timestamp (millis)
    pub last_heartbeat: i64,
    /// Whether the device is currently connected
    pub connected: bool,
}

/// Registry of known hardware devices.
pub struct DeviceRegistry {
    devices: HashMap<String, DeviceDescriptor>,
    /// Stale threshold in ms — devices with no heartbeat beyond this are marked stale
    stale_threshold_ms: i64,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            stale_threshold_ms: 30_000, // 30 seconds
        }
    }

    pub fn with_stale_threshold(mut self, ms: i64) -> Self {
        self.stale_threshold_ms = ms;
        self
    }

    /// Register a new device.
    pub fn register(&mut self, device: DeviceDescriptor) {
        self.devices.insert(device.device_id.clone(), device);
    }

    /// Get a device by ID.
    pub fn get(&self, device_id: &str) -> CapsResult<&DeviceDescriptor> {
        self.devices
            .get(device_id)
            .ok_or_else(|| CapsError::DeviceError(format!("Device not found: {}", device_id)))
    }

    /// Record a heartbeat for a device.
    pub fn heartbeat(&mut self, device_id: &str) -> CapsResult<()> {
        let device = self.devices.get_mut(device_id)
            .ok_or_else(|| CapsError::DeviceError(format!("Device not found: {}", device_id)))?;
        device.last_heartbeat = chrono::Utc::now().timestamp_millis();
        device.connected = true;
        Ok(())
    }

    /// Discover devices by class.
    pub fn discover_by_class(&self, class: DeviceClass) -> Vec<&DeviceDescriptor> {
        self.devices.values().filter(|d| d.device_class == class && d.connected).collect()
    }

    /// Discover devices by capability.
    pub fn discover_by_capability(&self, capability_id: &str) -> Vec<&DeviceDescriptor> {
        self.devices.values()
            .filter(|d| d.connected && d.capabilities.contains(&capability_id.to_string()))
            .collect()
    }

    /// Remove stale devices (no heartbeat within threshold).
    pub fn remove_stale(&mut self) -> Vec<String> {
        let now = chrono::Utc::now().timestamp_millis();
        let stale: Vec<String> = self.devices.iter()
            .filter(|(_, d)| now - d.last_heartbeat > self.stale_threshold_ms)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale {
            self.devices.remove(id);
        }
        stale
    }

    /// Mark a device as disconnected.
    pub fn disconnect(&mut self, device_id: &str) {
        if let Some(d) = self.devices.get_mut(device_id) {
            d.connected = false;
        }
    }

    /// Check safety constraints for a device operation.
    pub fn check_safety(
        &self,
        device_id: &str,
        velocity: Option<f64>,
        force: Option<f64>,
        position: Option<(f64, f64)>,
    ) -> CapsResult<()> {
        let device = self.get(device_id)?;
        let safety = &device.safety;

        if let (Some(max_v), Some(v)) = (safety.max_velocity, velocity) {
            if v > max_v {
                return Err(CapsError::SafetyViolation(format!(
                    "Velocity {} exceeds max {} for device {}", v, max_v, device_id
                )));
            }
        }

        if let (Some(max_f), Some(f)) = (safety.max_force, force) {
            if f > max_f {
                return Err(CapsError::SafetyViolation(format!(
                    "Force {} exceeds max {} for device {}", f, max_f, device_id
                )));
            }
        }

        if let (Some((min_x, min_y, max_x, max_y)), Some((x, y))) = (safety.geofence, position) {
            if x < min_x || x > max_x || y < min_y || y > max_y {
                return Err(CapsError::SafetyViolation(format!(
                    "Position ({}, {}) outside geofence for device {}", x, y, device_id
                )));
            }
        }

        Ok(())
    }

    pub fn len(&self) -> usize { self.devices.len() }
    pub fn is_empty(&self) -> bool { self.devices.is_empty() }
}

impl Default for DeviceRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(id: &str, class: DeviceClass) -> DeviceDescriptor {
        DeviceDescriptor {
            device_id: id.to_string(),
            device_class: class,
            interface: InterfaceProtocol::RawBytes,
            capabilities: vec!["hw.gpio_read".into(), "hw.gpio_write".into()],
            safety: SafetyConstraints {
                max_velocity: Some(10.0),
                max_force: Some(50.0),
                emergency_stop: true,
                watchdog_timeout_ms: Some(5000),
                geofence: Some((0.0, 0.0, 100.0, 100.0)),
                max_ops_per_second: Some(100),
            },
            description: "Test GPIO device".to_string(),
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            connected: true,
        }
    }

    #[test]
    fn test_device_register_and_get() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));
        assert_eq!(reg.len(), 1);
        assert!(reg.get("gpio-1").is_ok());
        assert!(reg.get("nonexistent").is_err());
    }

    #[test]
    fn test_device_discover_by_class() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));
        reg.register(make_device("gpio-2", DeviceClass::Gpio));
        reg.register(make_device("serial-1", DeviceClass::Serial));

        assert_eq!(reg.discover_by_class(DeviceClass::Gpio).len(), 2);
        assert_eq!(reg.discover_by_class(DeviceClass::Serial).len(), 1);
        assert_eq!(reg.discover_by_class(DeviceClass::I2c).len(), 0);
    }

    #[test]
    fn test_device_heartbeat() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));
        assert!(reg.heartbeat("gpio-1").is_ok());
        assert!(reg.heartbeat("nonexistent").is_err());
    }

    #[test]
    fn test_device_stale_removal() {
        let mut reg = DeviceRegistry::new().with_stale_threshold(0); // instant stale
        let mut dev = make_device("gpio-1", DeviceClass::Gpio);
        dev.last_heartbeat = chrono::Utc::now().timestamp_millis() - 1000;
        reg.register(dev);

        let stale = reg.remove_stale();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], "gpio-1");
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn test_device_safety_velocity() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));

        assert!(reg.check_safety("gpio-1", Some(5.0), None, None).is_ok());
        assert!(reg.check_safety("gpio-1", Some(15.0), None, None).is_err());
    }

    #[test]
    fn test_device_safety_force() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));

        assert!(reg.check_safety("gpio-1", None, Some(30.0), None).is_ok());
        assert!(reg.check_safety("gpio-1", None, Some(60.0), None).is_err());
    }

    #[test]
    fn test_device_safety_geofence() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));

        assert!(reg.check_safety("gpio-1", None, None, Some((50.0, 50.0))).is_ok());
        assert!(reg.check_safety("gpio-1", None, None, Some((150.0, 50.0))).is_err());
    }

    #[test]
    fn test_device_disconnect() {
        let mut reg = DeviceRegistry::new();
        reg.register(make_device("gpio-1", DeviceClass::Gpio));
        assert_eq!(reg.discover_by_class(DeviceClass::Gpio).len(), 1);

        reg.disconnect("gpio-1");
        assert_eq!(reg.discover_by_class(DeviceClass::Gpio).len(), 0);
    }
}
