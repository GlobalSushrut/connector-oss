# Gloo Roadmap

`gloo` is the Python-first developer layer on top of Connector.

## Goal

Give developers an "agentic app" workflow similar to a mobile app SDK:

- scaffold a project
- write Python code
- define agents and workflows
- connect to a local or remote Connector node
- bootstrap workflows and install packages
- eventually build and publish Connector-native `.cpkg` apps

## Milestone 1: foundation in this repo

This milestone adds:

- `connector_sdk.gloo`
- `GlooAppManifest`
- `GlooNode`
- `GlooProject.init_python_app()`
- `gloo` CLI
- real workflow bootstrap through `/api/v1/workflows/bootstrap`
- real existing-`.cpkg` install through `/api/v1/plugins/cpkg/install`

## Milestone 2

- package manifest validation
- agent/workflow apply from `gloo.json`
- project dev loop commands
- node capability discovery

## Milestone 3

- source-to-`.cpkg` build pipeline (`gloo build` / `GlooProject.build_cpkg` + `cnktros app`)
- package lifecycle hooks
- app publish/install UX in the dashboard

## Honesty

`gloo build` emits a real `.cpkg` + `.package.pin.json`. Production apply/install requires that pin; `--lab` is labeled lab-only.
