# MicroVM tool & world channels

The agentic brain never holds a direct host path to tools or devices. Effects leave
Connector only through a **microVM channel**.

## Channels via microVM

| Channel | Examples | Env |
| --- | --- | --- |
| Local I/O | shell, read/write file, exec | `CONNECTOR_TOOLS_IN_MICROVM=1` |
| Robotics | `robot:…`, `robot_hal`, ROS/HAL tools | `CONNECTOR_WORLD_CHANNEL_VIA_MICROVM=1` |
| IoT | `iot:…`, sensors/actuators | same |
| MQTT / Modbus | `mqtt://…`, `modbus:…` | same |
| Machine / device | `machine:…`, CNC, PLC | same |

Production defaults set both flags. Remote MCP HTTPS may remain a host broker only when
`CONNECTOR_ALLOW_HOST_MCP_BROKER=1` — it still cannot do local I/O or physical channels on the host.

## Flow

```text
LLM / agentic brain
        │
        ▼
 Connector admission (identity, HITL, ZT handshake, grants)
        │
        ▼
   microVM guest channel
        │
        ├── local I/O
        ├── robot HAL
        ├── IoT gateway
        └── MQTT / Modbus / machine
```

## APIs

- `GET /api/v1/runtime/microvm-tools/status`
- `POST /api/v1/runtime/microvm-tools/invoke` — local I/O job
- `POST /api/v1/protocol/conp/command` — physical CONP routes via microVM when flags on

## Assets

Set `CONNECTOR_MICROVM_KERNEL` and `CONNECTOR_MICROVM_ROOTFS`. Missing assets fail closed
(quarantine under distrust).

## Break-glass

- `CONNECTOR_ALLOW_IN_PROCESS_EFFECTS=1` — weakens claim
- `CONNECTOR_TOOLS_IN_MICROVM_STRICT=1` — also refuses host MCP broker
