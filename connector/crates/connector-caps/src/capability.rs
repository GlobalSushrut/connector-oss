//! Capability Registry — type-safe registry of all atomic operations an agent can perform.
//!
//! 10 categories, 84 capabilities covering filesystem, network, process, browser,
//! store, crypto, hardware, GPU, sensor, and actuator operations.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{CapsError, CapsResult};

// ── Enums ───────────────────────────────────────────────────────────

/// Risk level for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Capability category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityCategory {
    Filesystem,
    Network,
    Process,
    Browser,
    Store,
    Crypto,
    Hardware,
    Gpu,
    Sensor,
    Actuator,
}

impl std::fmt::Display for CapabilityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filesystem => write!(f, "fs"),
            Self::Network => write!(f, "net"),
            Self::Process => write!(f, "proc"),
            Self::Browser => write!(f, "browser"),
            Self::Store => write!(f, "store"),
            Self::Crypto => write!(f, "crypto"),
            Self::Hardware => write!(f, "hw"),
            Self::Gpu => write!(f, "gpu"),
            Self::Sensor => write!(f, "sensor"),
            Self::Actuator => write!(f, "actuator"),
        }
    }
}

/// Device class for hardware capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceClass {
    Gpio,
    Serial,
    I2c,
    Spi,
    Usb,
    Bluetooth,
    Zigbee,
    Mqtt,
    Modbus,
    Canbus,
    Ros2,
    GpuCompute,
    Fpga,
    Camera,
    Audio,
    Custom,
}

/// Interface protocol for device communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceProtocol {
    RawBytes,
    PubSub,
    Rpc,
    Stream,
    Mmio,
}

// ── Capability ──────────────────────────────────────────────────────

/// A single capability definition — an atomic operation an agent can perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// Unique identifier (e.g. "fs.read", "net.http_get", "hw.gpio_write")
    pub id: String,
    /// Category this capability belongs to
    pub category: CapabilityCategory,
    /// Risk level
    pub risk: RiskLevel,
    /// Whether the operation is reversible
    pub reversible: bool,
    /// Which runners can execute this capability
    pub supported_runners: Vec<String>,
    /// JSON Schema for parameters
    pub param_schema: serde_json::Value,
    /// Postcondition descriptions
    pub postconditions: Vec<String>,
    /// Device class (for hardware capabilities)
    pub device_class: Option<DeviceClass>,
    /// Interface protocol (for hardware capabilities)
    pub interface_protocol: Option<InterfaceProtocol>,
    /// Human-readable description
    pub description: String,
}

// ── Capability Registry ─────────────────────────────────────────────

/// Registry of all known capabilities.
pub struct CapabilityRegistry {
    capabilities: HashMap<String, Capability>,
}

impl CapabilityRegistry {
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
        }
    }

    /// Create a registry pre-loaded with all 84 standard capabilities.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();
        reg.register_defaults();
        reg
    }

    /// Register a capability.
    pub fn register(&mut self, cap: Capability) {
        self.capabilities.insert(cap.id.clone(), cap);
    }

    /// Lookup a capability by ID.
    pub fn get(&self, id: &str) -> CapsResult<&Capability> {
        self.capabilities
            .get(id)
            .ok_or_else(|| CapsError::CapabilityNotFound(id.to_string()))
    }

    /// List all capabilities in a category.
    pub fn list_by_category(&self, category: CapabilityCategory) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.category == category)
            .collect()
    }

    /// List all capabilities with a specific device class.
    pub fn list_by_device_class(&self, class: DeviceClass) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.device_class == Some(class))
            .collect()
    }

    /// List all capabilities at or above a risk level.
    pub fn list_by_min_risk(&self, min_risk: RiskLevel) -> Vec<&Capability> {
        self.capabilities
            .values()
            .filter(|c| c.risk >= min_risk)
            .collect()
    }

    /// Validate parameters against a capability's schema (basic type check).
    pub fn validate_params(&self, cap_id: &str, params: &serde_json::Value) -> CapsResult<()> {
        let cap = self.get(cap_id)?;
        if let Some(required) = cap.param_schema.get("required") {
            if let Some(required_arr) = required.as_array() {
                for req in required_arr {
                    if let Some(field) = req.as_str() {
                        if params.get(field).is_none() {
                            return Err(CapsError::InvalidParams(format!(
                                "Missing required parameter '{}' for capability '{}'",
                                field, cap_id
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Total number of registered capabilities.
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Register all 84 default capabilities across 10 categories.
    fn register_defaults(&mut self) {
        // ── Filesystem (10) ─────────────────────────────────
        for (id, desc, risk, reversible) in [
            ("fs.read", "Read file contents", RiskLevel::Low, false),
            ("fs.write", "Write file contents", RiskLevel::Medium, true),
            ("fs.append", "Append to file", RiskLevel::Medium, true),
            ("fs.delete", "Delete file", RiskLevel::High, true),
            ("fs.mkdir", "Create directory", RiskLevel::Low, true),
            ("fs.rmdir", "Remove directory", RiskLevel::High, true),
            ("fs.copy", "Copy file", RiskLevel::Medium, true),
            ("fs.move", "Move/rename file", RiskLevel::Medium, true),
            ("fs.list", "List directory contents", RiskLevel::Low, false),
            ("fs.stat", "Get file metadata", RiskLevel::Low, false),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Filesystem,
                risk,
                reversible,
                supported_runners: vec!["linux".into(), "container".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Network (7) ─────────────────────────────────────
        for (id, desc, risk) in [
            ("net.http_get", "HTTP GET request", RiskLevel::Medium),
            ("net.http_post", "HTTP POST request", RiskLevel::Medium),
            ("net.http_put", "HTTP PUT request", RiskLevel::Medium),
            ("net.http_delete", "HTTP DELETE request", RiskLevel::High),
            ("net.websocket", "WebSocket connection", RiskLevel::Medium),
            ("net.dns_resolve", "DNS resolution", RiskLevel::Low),
            ("net.tcp_connect", "Raw TCP connection", RiskLevel::High),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Network,
                risk,
                reversible: false,
                supported_runners: vec!["http".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Process (8) ─────────────────────────────────────
        for (id, desc, risk) in [
            ("proc.spawn", "Spawn subprocess", RiskLevel::High),
            ("proc.exec", "Execute command", RiskLevel::High),
            ("proc.kill", "Kill process", RiskLevel::Critical),
            ("proc.signal", "Send signal to process", RiskLevel::High),
            ("proc.env_read", "Read environment variable", RiskLevel::Low),
            ("proc.env_write", "Set environment variable", RiskLevel::Medium),
            ("proc.cwd", "Get current working directory", RiskLevel::Low),
            ("proc.pid", "Get process ID", RiskLevel::Low),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Process,
                risk,
                reversible: false,
                supported_runners: vec!["linux".into(), "container".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"command": {"type": "string"}}}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Browser (13) ────────────────────────────────────
        for (id, desc, risk) in [
            ("browser.navigate", "Navigate to URL", RiskLevel::Medium),
            ("browser.click", "Click element", RiskLevel::Medium),
            ("browser.type", "Type text into element", RiskLevel::Medium),
            ("browser.screenshot", "Take screenshot", RiskLevel::Low),
            ("browser.extract", "Extract text from page", RiskLevel::Low),
            ("browser.eval_js", "Evaluate JavaScript", RiskLevel::High),
            ("browser.cookie_read", "Read cookies", RiskLevel::Medium),
            ("browser.cookie_write", "Write cookies", RiskLevel::High),
            ("browser.storage_read", "Read local storage", RiskLevel::Medium),
            ("browser.storage_write", "Write local storage", RiskLevel::High),
            ("browser.download", "Download file", RiskLevel::Medium),
            ("browser.upload", "Upload file", RiskLevel::High),
            ("browser.pdf", "Generate PDF", RiskLevel::Low),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Browser,
                risk,
                reversible: false,
                supported_runners: vec!["browser".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"selector": {"type": "string"}}}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Store (5) ───────────────────────────────────────
        for (id, desc, risk) in [
            ("store.read", "Read from VAC namespace", RiskLevel::Low),
            ("store.write", "Write to VAC namespace", RiskLevel::Medium),
            ("store.delete", "Delete from VAC namespace", RiskLevel::High),
            ("store.query", "Query VAC namespace", RiskLevel::Low),
            ("store.compact", "Compact VAC storage", RiskLevel::Medium),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Store,
                risk,
                reversible: id.contains("write") || id.contains("delete"),
                supported_runners: vec!["store".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Crypto (8) ──────────────────────────────────────
        for (id, desc, risk) in [
            ("crypto.hash", "Compute hash", RiskLevel::Low),
            ("crypto.sign", "Sign data", RiskLevel::Medium),
            ("crypto.verify", "Verify signature", RiskLevel::Low),
            ("crypto.encrypt", "Encrypt data", RiskLevel::Medium),
            ("crypto.decrypt", "Decrypt data", RiskLevel::Medium),
            ("crypto.keygen", "Generate key pair", RiskLevel::Medium),
            ("crypto.derive", "Derive key from master", RiskLevel::Medium),
            ("crypto.hmac", "Compute HMAC", RiskLevel::Low),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Crypto,
                risk,
                reversible: false,
                supported_runners: vec!["noop".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"algorithm": {"type": "string"}}}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: None,
                description: desc.to_string(),
            });
        }

        // ── Hardware (12) ───────────────────────────────────
        let hw_caps: Vec<(&str, &str, RiskLevel, DeviceClass, InterfaceProtocol)> = vec![
            ("hw.gpio_read", "Read GPIO pin", RiskLevel::Low, DeviceClass::Gpio, InterfaceProtocol::RawBytes),
            ("hw.gpio_write", "Write GPIO pin", RiskLevel::Medium, DeviceClass::Gpio, InterfaceProtocol::RawBytes),
            ("hw.serial_send", "Send via serial", RiskLevel::Medium, DeviceClass::Serial, InterfaceProtocol::Stream),
            ("hw.serial_recv", "Receive via serial", RiskLevel::Low, DeviceClass::Serial, InterfaceProtocol::Stream),
            ("hw.i2c_transfer", "I2C bus transfer", RiskLevel::Medium, DeviceClass::I2c, InterfaceProtocol::RawBytes),
            ("hw.spi_transfer", "SPI bus transfer", RiskLevel::Medium, DeviceClass::Spi, InterfaceProtocol::RawBytes),
            ("hw.usb_control", "USB control transfer", RiskLevel::High, DeviceClass::Usb, InterfaceProtocol::RawBytes),
            ("hw.bluetooth_scan", "Bluetooth scan", RiskLevel::Low, DeviceClass::Bluetooth, InterfaceProtocol::PubSub),
            ("hw.mqtt_publish", "MQTT publish", RiskLevel::Medium, DeviceClass::Mqtt, InterfaceProtocol::PubSub),
            ("hw.mqtt_subscribe", "MQTT subscribe", RiskLevel::Low, DeviceClass::Mqtt, InterfaceProtocol::PubSub),
            ("hw.modbus_read", "Modbus register read", RiskLevel::Low, DeviceClass::Modbus, InterfaceProtocol::Rpc),
            ("hw.modbus_write", "Modbus register write", RiskLevel::High, DeviceClass::Modbus, InterfaceProtocol::Rpc),
        ];
        for (id, desc, risk, dc, ip) in hw_caps {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Hardware,
                risk,
                reversible: false,
                supported_runners: vec!["device".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"device_id": {"type": "string"}}, "required": ["device_id"]}),
                postconditions: vec![],
                device_class: Some(dc),
                interface_protocol: Some(ip),
                description: desc.to_string(),
            });
        }

        // ── GPU (6) ─────────────────────────────────────────
        for (id, desc, risk) in [
            ("gpu.allocate", "Allocate GPU memory", RiskLevel::Medium),
            ("gpu.release", "Release GPU memory", RiskLevel::Low),
            ("gpu.transfer_h2d", "Transfer host to device", RiskLevel::Medium),
            ("gpu.transfer_d2h", "Transfer device to host", RiskLevel::Low),
            ("gpu.compute", "Launch compute kernel", RiskLevel::High),
            ("gpu.inference", "Run model inference", RiskLevel::High),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Gpu,
                risk,
                reversible: false,
                supported_runners: vec!["gpu".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"size_bytes": {"type": "integer"}}}),
                postconditions: vec![],
                device_class: Some(DeviceClass::GpuCompute),
                interface_protocol: Some(InterfaceProtocol::Mmio),
                description: desc.to_string(),
            });
        }

        // ── Sensor (8) ──────────────────────────────────────
        for (id, desc, risk) in [
            ("sensor.temperature", "Read temperature", RiskLevel::Low),
            ("sensor.humidity", "Read humidity", RiskLevel::Low),
            ("sensor.pressure", "Read pressure", RiskLevel::Low),
            ("sensor.accelerometer", "Read accelerometer", RiskLevel::Low),
            ("sensor.gyroscope", "Read gyroscope", RiskLevel::Low),
            ("sensor.gps", "Read GPS coordinates", RiskLevel::Medium),
            ("sensor.camera_capture", "Capture camera frame", RiskLevel::Medium),
            ("sensor.audio_capture", "Capture audio", RiskLevel::Medium),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Sensor,
                risk,
                reversible: false,
                supported_runners: vec!["device".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"device_id": {"type": "string"}}, "required": ["device_id"]}),
                postconditions: vec![],
                device_class: Some(DeviceClass::Camera),
                interface_protocol: Some(InterfaceProtocol::Stream),
                description: desc.to_string(),
            });
        }

        // ── Actuator (7) ────────────────────────────────────
        for (id, desc, risk) in [
            ("actuator.motor_set", "Set motor speed/position", RiskLevel::High),
            ("actuator.servo_set", "Set servo angle", RiskLevel::High),
            ("actuator.relay_on", "Turn relay on", RiskLevel::Medium),
            ("actuator.relay_off", "Turn relay off", RiskLevel::Medium),
            ("actuator.valve_open", "Open valve", RiskLevel::High),
            ("actuator.valve_close", "Close valve", RiskLevel::High),
            ("actuator.emergency_stop", "Emergency stop all actuators", RiskLevel::Critical),
        ] {
            self.register(Capability {
                id: id.to_string(),
                category: CapabilityCategory::Actuator,
                risk,
                reversible: true,
                supported_runners: vec!["device".into()],
                param_schema: serde_json::json!({"type": "object", "properties": {"device_id": {"type": "string"}, "value": {"type": "number"}}, "required": ["device_id"]}),
                postconditions: vec![],
                device_class: None,
                interface_protocol: Some(InterfaceProtocol::Rpc),
                description: desc.to_string(),
            });
        }
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_defaults_has_84_capabilities() {
        let reg = CapabilityRegistry::with_defaults();
        assert_eq!(reg.len(), 84, "Should have exactly 84 default capabilities");
    }

    #[test]
    fn test_registry_categories() {
        let reg = CapabilityRegistry::with_defaults();
        assert_eq!(reg.list_by_category(CapabilityCategory::Filesystem).len(), 10);
        assert_eq!(reg.list_by_category(CapabilityCategory::Network).len(), 7);
        assert_eq!(reg.list_by_category(CapabilityCategory::Process).len(), 8);
        assert_eq!(reg.list_by_category(CapabilityCategory::Browser).len(), 13);
        assert_eq!(reg.list_by_category(CapabilityCategory::Store).len(), 5);
        assert_eq!(reg.list_by_category(CapabilityCategory::Crypto).len(), 8);
        assert_eq!(reg.list_by_category(CapabilityCategory::Hardware).len(), 12);
        assert_eq!(reg.list_by_category(CapabilityCategory::Gpu).len(), 6);
        assert_eq!(reg.list_by_category(CapabilityCategory::Sensor).len(), 8);
        assert_eq!(reg.list_by_category(CapabilityCategory::Actuator).len(), 7);
    }

    #[test]
    fn test_registry_lookup() {
        let reg = CapabilityRegistry::with_defaults();
        let cap = reg.get("fs.read").unwrap();
        assert_eq!(cap.category, CapabilityCategory::Filesystem);
        assert_eq!(cap.risk, RiskLevel::Low);
        assert!(!cap.reversible);
    }

    #[test]
    fn test_registry_lookup_unknown() {
        let reg = CapabilityRegistry::with_defaults();
        assert!(reg.get("nonexistent").is_err());
    }

    #[test]
    fn test_registry_validate_params_ok() {
        let reg = CapabilityRegistry::with_defaults();
        let params = serde_json::json!({"path": "/tmp/test.txt"});
        assert!(reg.validate_params("fs.read", &params).is_ok());
    }

    #[test]
    fn test_registry_validate_params_missing_required() {
        let reg = CapabilityRegistry::with_defaults();
        let params = serde_json::json!({});
        assert!(reg.validate_params("fs.read", &params).is_err());
    }

    #[test]
    fn test_registry_device_class_filter() {
        let reg = CapabilityRegistry::with_defaults();
        let gpio_caps = reg.list_by_device_class(DeviceClass::Gpio);
        assert_eq!(gpio_caps.len(), 2); // gpio_read, gpio_write
        for cap in &gpio_caps {
            assert!(cap.id.starts_with("hw.gpio"));
        }
    }

    #[test]
    fn test_registry_risk_filter() {
        let reg = CapabilityRegistry::with_defaults();
        let critical = reg.list_by_min_risk(RiskLevel::Critical);
        assert!(critical.len() >= 2); // proc.kill, actuator.emergency_stop
        for cap in &critical {
            assert_eq!(cap.risk, RiskLevel::Critical);
        }
    }

    #[test]
    fn test_registry_custom_capability() {
        let mut reg = CapabilityRegistry::new();
        reg.register(Capability {
            id: "custom.my_tool".to_string(),
            category: CapabilityCategory::Store,
            risk: RiskLevel::Low,
            reversible: false,
            supported_runners: vec!["noop".into()],
            param_schema: serde_json::json!({"type": "object"}),
            postconditions: vec![],
            device_class: None,
            interface_protocol: None,
            description: "My custom tool".to_string(),
        });
        assert_eq!(reg.len(), 1);
        assert!(reg.get("custom.my_tool").is_ok());
    }
}
