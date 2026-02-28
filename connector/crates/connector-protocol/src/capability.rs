//! Expanded Capability Taxonomy — 120 capabilities across 12 categories.
//!
//! Extends the base 84 capabilities with safety.* (16), machine.* (14),
//! and expanded agent.* capabilities.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::identity::EntityClass;
use crate::safety::SafetyIntegrityLevel;

// ── Risk Level ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// ── Capability Category ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityCategory {
    Agent,
    Machine,
    Device,
    Sensor,
    Actuator,
    Net,
    Fs,
    Proc,
    Store,
    Crypto,
    Gpu,
    Safety,
}

impl CapabilityCategory {
    /// Which entity classes are allowed to use capabilities in this category.
    pub fn allowed_entity_classes(&self) -> Vec<EntityClass> {
        match self {
            Self::Agent => vec![EntityClass::Agent, EntityClass::Service, EntityClass::Composite],
            Self::Machine => vec![EntityClass::Machine, EntityClass::Composite],
            Self::Device => vec![EntityClass::Device, EntityClass::Machine, EntityClass::Composite],
            Self::Sensor => vec![EntityClass::Sensor, EntityClass::Machine, EntityClass::Composite],
            Self::Actuator => vec![EntityClass::Actuator, EntityClass::Machine, EntityClass::Composite],
            Self::Safety => vec![
                EntityClass::Machine, EntityClass::Device, EntityClass::Sensor,
                EntityClass::Actuator, EntityClass::Composite, EntityClass::Agent,
                EntityClass::Service,
            ],
            _ => vec![
                EntityClass::Agent, EntityClass::Machine, EntityClass::Device,
                EntityClass::Service, EntityClass::Sensor, EntityClass::Actuator,
                EntityClass::Composite,
            ],
        }
    }
}

// ── Capability ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapability {
    pub id: String,
    pub category: CapabilityCategory,
    pub risk: RiskLevel,
    pub description: String,
    pub min_sil: SafetyIntegrityLevel,
    pub requires_realtime: bool,
}

// ── Registry ────────────────────────────────────────────────────────

pub struct ProtocolCapabilityRegistry {
    capabilities: HashMap<String, ProtocolCapability>,
}

impl ProtocolCapabilityRegistry {
    pub fn new() -> Self {
        Self { capabilities: HashMap::new() }
    }

    pub fn register(&mut self, cap: ProtocolCapability) {
        self.capabilities.insert(cap.id.clone(), cap);
    }

    pub fn get(&self, id: &str) -> Option<&ProtocolCapability> {
        self.capabilities.get(id)
    }

    pub fn list_by_category(&self, cat: CapabilityCategory) -> Vec<&ProtocolCapability> {
        self.capabilities.values().filter(|c| c.category == cat).collect()
    }

    pub fn count(&self) -> usize { self.capabilities.len() }

    pub fn count_by_category(&self, cat: CapabilityCategory) -> usize {
        self.capabilities.values().filter(|c| c.category == cat).count()
    }

    /// Check if an entity class is allowed to use a capability.
    pub fn is_allowed(&self, cap_id: &str, entity_class: EntityClass) -> bool {
        self.capabilities.get(cap_id)
            .map(|c| c.category.allowed_entity_classes().contains(&entity_class))
            .unwrap_or(false)
    }

    /// Build the full 120-capability registry.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();

        // agent.* (15)
        for (id, risk, desc) in [
            ("agent.reason", RiskLevel::Low, "Reasoning and inference"),
            ("agent.plan", RiskLevel::Low, "Planning and goal decomposition"),
            ("agent.delegate", RiskLevel::Medium, "Delegate task to another agent"),
            ("agent.recall", RiskLevel::Low, "Recall from memory"),
            ("agent.remember", RiskLevel::Low, "Write to memory"),
            ("agent.observe", RiskLevel::Low, "Observe environment state"),
            ("agent.decide", RiskLevel::Medium, "Make a decision"),
            ("agent.coordinate", RiskLevel::Medium, "Multi-agent coordination"),
            ("agent.spawn", RiskLevel::High, "Spawn a sub-agent"),
            ("agent.terminate", RiskLevel::High, "Terminate an agent"),
            ("agent.trust_evaluate", RiskLevel::Low, "Evaluate trust score"),
            ("agent.port_send", RiskLevel::Medium, "Send message via port"),
            ("agent.port_receive", RiskLevel::Low, "Receive message via port"),
            ("agent.session_create", RiskLevel::Medium, "Create a new session"),
            ("agent.session_close", RiskLevel::Low, "Close a session"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Agent, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // machine.* (14)
        for (id, risk, desc) in [
            ("machine.spindle_on", RiskLevel::High, "Start spindle motor"),
            ("machine.spindle_off", RiskLevel::Medium, "Stop spindle motor"),
            ("machine.move_axis", RiskLevel::High, "Move machine axis"),
            ("machine.home", RiskLevel::Medium, "Home all axes"),
            ("machine.probe", RiskLevel::Medium, "Touch probe cycle"),
            ("machine.tool_change", RiskLevel::High, "Change cutting tool"),
            ("machine.coolant", RiskLevel::Low, "Control coolant system"),
            ("machine.clamp", RiskLevel::Medium, "Engage workholding clamp"),
            ("machine.unclamp", RiskLevel::Medium, "Release workholding clamp"),
            ("machine.park", RiskLevel::Low, "Park to safe position"),
            ("machine.jog", RiskLevel::High, "Manual jog mode"),
            ("machine.rapid", RiskLevel::Critical, "Rapid traverse movement"),
            ("machine.arc", RiskLevel::High, "Circular interpolation"),
            ("machine.program_run", RiskLevel::Critical, "Execute G-code program"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Machine, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL2,
                requires_realtime: true,
            });
        }

        // device.* (12)
        for (id, risk, desc) in [
            ("device.gpio_read", RiskLevel::Low, "Read GPIO pin"),
            ("device.gpio_write", RiskLevel::Medium, "Write GPIO pin"),
            ("device.i2c_read", RiskLevel::Low, "Read I2C bus"),
            ("device.i2c_write", RiskLevel::Medium, "Write I2C bus"),
            ("device.spi_transfer", RiskLevel::Medium, "SPI bus transfer"),
            ("device.serial_read", RiskLevel::Low, "Read serial port"),
            ("device.serial_write", RiskLevel::Medium, "Write serial port"),
            ("device.usb_read", RiskLevel::Low, "Read USB device"),
            ("device.usb_write", RiskLevel::Medium, "Write USB device"),
            ("device.bluetooth_connect", RiskLevel::Medium, "Connect Bluetooth"),
            ("device.bluetooth_send", RiskLevel::Medium, "Send Bluetooth data"),
            ("device.can_send", RiskLevel::High, "Send CAN bus message"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Device, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL1,
                requires_realtime: true,
            });
        }

        // sensor.* (10)
        for (id, desc) in [
            ("sensor.temperature", "Read temperature sensor"),
            ("sensor.pressure", "Read pressure sensor"),
            ("sensor.imu", "Read IMU (accelerometer/gyroscope)"),
            ("sensor.lidar", "Read LIDAR scanner"),
            ("sensor.camera", "Capture camera image"),
            ("sensor.gps", "Read GPS position"),
            ("sensor.force", "Read force/torque sensor"),
            ("sensor.proximity", "Read proximity sensor"),
            ("sensor.encoder", "Read rotary/linear encoder"),
            ("sensor.analog", "Read analog input"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Sensor, risk: RiskLevel::Low,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL1,
                requires_realtime: true,
            });
        }

        // actuator.* (10)
        for (id, risk, desc) in [
            ("actuator.motor_run", RiskLevel::High, "Run motor"),
            ("actuator.motor_stop", RiskLevel::Medium, "Stop motor"),
            ("actuator.servo_position", RiskLevel::High, "Set servo position"),
            ("actuator.valve_open", RiskLevel::High, "Open valve"),
            ("actuator.valve_close", RiskLevel::Medium, "Close valve"),
            ("actuator.relay_on", RiskLevel::Medium, "Energize relay"),
            ("actuator.relay_off", RiskLevel::Low, "De-energize relay"),
            ("actuator.pump_on", RiskLevel::High, "Start pump"),
            ("actuator.pump_off", RiskLevel::Medium, "Stop pump"),
            ("actuator.heater", RiskLevel::High, "Control heater element"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Actuator, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL2,
                requires_realtime: true,
            });
        }

        // net.* (8)
        for (id, risk, desc) in [
            ("net.http", RiskLevel::Medium, "HTTP request"),
            ("net.websocket", RiskLevel::Medium, "WebSocket connection"),
            ("net.tcp", RiskLevel::Medium, "Raw TCP connection"),
            ("net.dns", RiskLevel::Low, "DNS lookup"),
            ("net.mqtt_publish", RiskLevel::Medium, "MQTT publish"),
            ("net.mqtt_subscribe", RiskLevel::Low, "MQTT subscribe"),
            ("net.modbus_read", RiskLevel::Medium, "Modbus TCP read"),
            ("net.modbus_write", RiskLevel::High, "Modbus TCP write"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Net, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // fs.* (8)
        for (id, risk, desc) in [
            ("fs.read", RiskLevel::Low, "Read file"),
            ("fs.write", RiskLevel::Medium, "Write file"),
            ("fs.delete", RiskLevel::High, "Delete file"),
            ("fs.list", RiskLevel::Low, "List directory"),
            ("fs.stat", RiskLevel::Low, "File metadata"),
            ("fs.watch", RiskLevel::Low, "Watch for changes"),
            ("fs.mount", RiskLevel::Critical, "Mount filesystem"),
            ("fs.unmount", RiskLevel::High, "Unmount filesystem"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Fs, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // proc.* (7)
        for (id, risk, desc) in [
            ("proc.spawn", RiskLevel::High, "Spawn process"),
            ("proc.exec", RiskLevel::Critical, "Execute binary"),
            ("proc.kill", RiskLevel::High, "Kill process"),
            ("proc.signal", RiskLevel::Medium, "Send signal"),
            ("proc.env_read", RiskLevel::Low, "Read environment"),
            ("proc.env_write", RiskLevel::High, "Write environment"),
            ("proc.cgroup", RiskLevel::Critical, "Manage cgroups"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Proc, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // store.* (6)
        for (id, risk, desc) in [
            ("store.read", RiskLevel::Low, "Read from store"),
            ("store.write", RiskLevel::Medium, "Write to store"),
            ("store.delete", RiskLevel::High, "Delete from store"),
            ("store.query", RiskLevel::Low, "Query store"),
            ("store.compact", RiskLevel::Medium, "Compact store"),
            ("store.snapshot", RiskLevel::Medium, "Create snapshot"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Store, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // crypto.* (8)
        for (id, risk, desc) in [
            ("crypto.hash", RiskLevel::Low, "Compute hash"),
            ("crypto.sign", RiskLevel::Medium, "Sign data"),
            ("crypto.verify", RiskLevel::Low, "Verify signature"),
            ("crypto.encrypt", RiskLevel::Medium, "Encrypt data"),
            ("crypto.decrypt", RiskLevel::High, "Decrypt data"),
            ("crypto.keygen", RiskLevel::High, "Generate key pair"),
            ("crypto.derive", RiskLevel::Medium, "Derive key"),
            ("crypto.attest", RiskLevel::Medium, "Create attestation"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Crypto, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // gpu.* (6)
        for (id, risk, desc) in [
            ("gpu.allocate", RiskLevel::Medium, "Allocate GPU memory"),
            ("gpu.release", RiskLevel::Low, "Release GPU memory"),
            ("gpu.transfer_h2d", RiskLevel::Medium, "Host to device transfer"),
            ("gpu.transfer_d2h", RiskLevel::Low, "Device to host transfer"),
            ("gpu.compute", RiskLevel::High, "Launch compute kernel"),
            ("gpu.inference", RiskLevel::Medium, "Run ML inference"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Gpu, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: false,
            });
        }

        // safety.* (16) — PRIVILEGED
        for (id, risk, desc) in [
            ("safety.emergency_stop", RiskLevel::Low, "Emergency stop (ambient, no token needed)"),
            ("safety.watchdog_reset", RiskLevel::Low, "Reset watchdog timer"),
            ("safety.geofence_check", RiskLevel::Low, "Check geofence boundary"),
            ("safety.heartbeat", RiskLevel::Low, "Safety heartbeat"),
            ("safety.force_limit", RiskLevel::Low, "Check force limits"),
            ("safety.velocity_limit", RiskLevel::Low, "Check velocity limits"),
            ("safety.collision_check", RiskLevel::Low, "Check for collisions"),
            ("safety.interlock", RiskLevel::Medium, "Manage interlocks"),
            ("safety.lockout_tagout", RiskLevel::High, "Lock out equipment"),
            ("safety.sil_validate", RiskLevel::Low, "Validate SIL compliance"),
            ("safety.fault_report", RiskLevel::Low, "Report safety fault"),
            ("safety.safe_state", RiskLevel::Medium, "Transition to safe state"),
            ("safety.redundancy_check", RiskLevel::Low, "Check redundant systems"),
            ("safety.diagnostic", RiskLevel::Low, "Run safety diagnostic"),
            ("safety.calibrate", RiskLevel::Medium, "Calibrate safety system"),
            ("safety.self_test", RiskLevel::Low, "Run safety self-test"),
        ] {
            reg.register(ProtocolCapability {
                id: id.into(), category: CapabilityCategory::Safety, risk,
                description: desc.into(), min_sil: SafetyIntegrityLevel::SIL0,
                requires_realtime: true,
            });
        }

        reg
    }
}

impl Default for ProtocolCapabilityRegistry {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_120_capabilities() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        assert_eq!(reg.count(), 120);
    }

    #[test]
    fn test_category_counts() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        assert_eq!(reg.count_by_category(CapabilityCategory::Agent), 15);
        assert_eq!(reg.count_by_category(CapabilityCategory::Machine), 14);
        assert_eq!(reg.count_by_category(CapabilityCategory::Device), 12);
        assert_eq!(reg.count_by_category(CapabilityCategory::Sensor), 10);
        assert_eq!(reg.count_by_category(CapabilityCategory::Actuator), 10);
        assert_eq!(reg.count_by_category(CapabilityCategory::Net), 8);
        assert_eq!(reg.count_by_category(CapabilityCategory::Fs), 8);
        assert_eq!(reg.count_by_category(CapabilityCategory::Proc), 7);
        assert_eq!(reg.count_by_category(CapabilityCategory::Store), 6);
        assert_eq!(reg.count_by_category(CapabilityCategory::Crypto), 8);
        assert_eq!(reg.count_by_category(CapabilityCategory::Gpu), 6);
        assert_eq!(reg.count_by_category(CapabilityCategory::Safety), 16);
    }

    #[test]
    fn test_lookup() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        let cap = reg.get("machine.move_axis").unwrap();
        assert_eq!(cap.risk, RiskLevel::High);
        assert!(cap.requires_realtime);
        assert_eq!(cap.min_sil, SafetyIntegrityLevel::SIL2);
    }

    #[test]
    fn test_safety_capabilities() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        let estop = reg.get("safety.emergency_stop").unwrap();
        assert_eq!(estop.risk, RiskLevel::Low); // ambient, always allowed
        assert_eq!(estop.category, CapabilityCategory::Safety);
    }

    #[test]
    fn test_entity_class_filtering() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        // Agent can use agent.* capabilities
        assert!(reg.is_allowed("agent.reason", EntityClass::Agent));
        // Agent cannot use machine.* capabilities
        assert!(!reg.is_allowed("machine.move_axis", EntityClass::Agent));
        // Machine can use machine.* capabilities
        assert!(reg.is_allowed("machine.move_axis", EntityClass::Machine));
        // Everyone can use safety.*
        assert!(reg.is_allowed("safety.emergency_stop", EntityClass::Agent));
        assert!(reg.is_allowed("safety.emergency_stop", EntityClass::Machine));
    }

    #[test]
    fn test_machine_realtime_requirement() {
        let reg = ProtocolCapabilityRegistry::with_defaults();
        let machine_caps = reg.list_by_category(CapabilityCategory::Machine);
        for cap in machine_caps {
            assert!(cap.requires_realtime, "machine.* should require realtime: {}", cap.id);
        }
    }
}
