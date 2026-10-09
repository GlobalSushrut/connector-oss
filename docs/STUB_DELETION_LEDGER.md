# Production stub deletion ledger (Phase 12)

Each row: stub id, owner, replacement path, status.
Status: open | migrated | deleted | lab_only

| Stub ID | Location | Replacement | Status |
|---------|----------|-------------|--------|
| attached_app_not_implemented | extension_host.rs | AttachedApp bind/activate + package pin | migrated |
| native_invoker_local_gate | native_invoker.rs | substrate/package_gate.rs | migrated |
| gloo_apply_unpackaged | gloo/project.py resolve_cpkg_for_apply | package pin required | migrated |
| workflow_enable_no_pin | workflow_runtime.rs ENABLE | package on TransitionWorkflowRequest | migrated |
| mcp_register_no_pin | tools.rs mcp_register | package in JSON body | migrated |
| proxy_route_no_pin | proxy_plane.rs put_route_graph | RouteGraph.package | migrated |
| protocol_driver_no_package_forward | protocol_drivers/mod.rs | ProtocolEffect.package → native_invoker | migrated |
| protocol_driver_conp_cnp_skip_gate | protocol_drivers + CONP/CNP/A2A handlers | `gate_mutating_package` before PATE (receipt envelope still non-mutating) | migrated |
| in_process_world_dials | MCP/HAL/Talk on platform PID | `landlock_child` + `pore_table` dest pin (iptables-like default DROP) | migrated |
| api_error_unstructured | channel_surface / proxy_plane | ApiErrorEnvelope + deny_json | migrated |
| cls_bytecode_vm | platform/server/src/cls | ConnectorIrV1 + compile_ccl (connector-engine) | deleted |
| glue_protocol_stub | platform/server/src/protocols/glue.rs | protocol_drivers | deleted |
| contract_executor_no_store | connector-engine cls/executor.rs | ExecutionStore + with_store | migrated |
| workflow_runner_blueprint | workflow_cls_execution.rs | ContractExecutor + EngineStoreExecutionSink | migrated |
| proxy_embedded_noop | proxy_plane.rs Embedded hop | embedded_forward + lease | migrated |
| proxy_envoy_deferred | proxy_plane.rs Envoy hop | compile_envoy_xds_snapshot (execute still deferred) | open |
| kerneld_lease_count | flow_lease.rs / kerneld | kernel_cage_hostnames + flow_lease_cage_hostnames | migrated |
| sdk_fake_delegation | connector-api agent.rs | send_to/delegate_to fail-closed → ConnectorClient::invoke | migrated |
| gloo_agent_graph_api | gloo/authoring.py | Agent/Tool/Graph → specs + .cpkg | migrated |
| ts_sdk_parity | platform/sdk/typescript/gloo-authoring | identical ToolSpec digests | migrated |
| evidence_graph_missing | substrate | evidence_graph dual-write + /native/evidence/graph | migrated |
| envoy_xds | proxy_plane compile_envoy_xds_snapshot | CDS/RDS snapshot on put_route + Envoy hop | migrated |
| full_security_conformance | package_gate + channel_surface tenant bind | security_conformance_package_gate + JWT tenant | migrated |
| performance_economics | native_invoker + proxy_plane | phases_ms, write-amp, latency, hop_budget | migrated |
| monitor_native_unwired | router.rs | /monitor/native[+charts] | migrated |
| stub_pate_facade | channel_surface.rs | cfg(test) only; HTTP → native_invoker | deleted |
| protocol_driver_fake_ok | protocol_drivers hop | effect_executed:false / admit_observe | migrated |
| budget_spec_unwired | native_invoker + trajectory_budget | BudgetSpec narrows ceilings | migrated |
| envoy_xds_file_dump | proxy_plane put_route_graph | data_dir/envoy_xds file_only | migrated |
| py_sdk_native_gap | connector_sdk/native.py | NativeClient + package gate | migrated |
| cls_stub_handlers | workflow_cls_execution | PlatformTool/LLM/Memory/Message handlers | migrated |
| glue_cid_fake_success | connector-glue runtime.rs | CID targets Err; lab stub honesty labeled | migrated |
| ts_native_client_gap | sdk/typescript/native | NativeClient parity with Python | migrated |
| attached_app_run_attach | extension_host.rs | run (birth-controlled) + attach (advisory) | migrated |
| wit_component_link | extension_wit.rs | require_component_link_or_err + declared artifact | lab_only |
