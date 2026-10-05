//! Command registry and top-level dispatch.

use crate::access;
use crate::data;
use crate::govern;
use crate::iia;
use crate::node;
use crate::output::{CmdResult, ExitCode, GlobalOpts, Provenance, human_lines};
use crate::product;
use crate::substrate;
use crate::workload;
use serde_json::json;

pub fn print_help(opts: &GlobalOpts) {
    let text = help_text();
    if opts.output == crate::output::OutputMode::Json {
        let _ = CmdResult {
            ok: true,
            command: "help".into(),
            exit: ExitCode::Success,
            source: Provenance::host("builtin help"),
            data: json!({ "help": text }),
            warnings: vec![],
            error: None,
        }
        .emit(opts);
    } else {
        print!("{text}");
    }
}

fn help_text() -> String {
    format!(
        "connectorctl — Connector Platform operator CLI\n\
         \n\
         USAGE:\n\
           connectorctl [global-flags] <namespace> <verb> [args]\n\
           connectorctl [global-flags] <compat-verb> [args]\n\
         \n\
         GLOBAL FLAGS:\n\
           --endpoint URL          Node base URL (env CONNECTOR_API_URL)\n\
           --api-key-file PATH     Bearer token file (env CONNECTOR_API_KEY_FILE)\n\
           --timeout SECS          HTTP timeout (env CONNECTOR_TIMEOUT)\n\
           --output human|json     Machine or human output (--json)\n\
           --no-color              Disable ANSI\n\
           --yes                   Confirm destructive actions\n\
         \n\
         NAMESPACES:\n\
           node       start|stop|restart|status|health|doctor|logs|support-bundle|config\n\
           data       backup|restore|upgrade|storage\n\
           workload   list|show|deploy|start|stop|logs|inspect\n\
           govern     policy|compliance|cost|metrics|events|aipsprt|spend|backends|deploy-verify|ecosystem|explain|cease-proof\n\
           product    install|start|stop|restart|upgrade|rollback|status|diagnose|uninstall|reconcile|demo|providers|compatibility\n\
           substrate  status|arc|svf|dal|rollup|worldline\n\
           access     status|mode|activate|pilot|license\n\
           iia        smoke [--conp]\n\
         \n\
         META:\n\
           version | help | completion bash|zsh|fish\n\
         \n\
         COMPAT (one release): status health doctor logs backup restore support-bundle\n\
           map to the matching namespace verbs.\n\
         \n\
         Version {}\n",
        env!("CARGO_PKG_VERSION")
    )
}

pub fn dispatch(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let head = args[0].as_str();
    let rest = &args[1..];

    match head {
        "help" | "--help" | "-h" => {
            if rest.is_empty() {
                print_help(opts);
                Ok(ExitCode::Success)
            } else {
                namespace_help(opts, &rest[0])
            }
        }
        "version" | "--version" | "-V" => version(opts),
        "completion" => completion(opts, rest),

        "node" => node::run(opts, rest),
        "data" => data::run(opts, rest),
        "workload" => workload::run(opts, rest),
        "govern" => govern::run(opts, rest),
        "product" => product::run(opts, rest),
        "substrate" => substrate::run(opts, rest),
        "access" => access::run(opts, rest),
        "iia" => iia::run(opts, rest),

        // Compatibility shims (bare verbs → namespaces)
        "status" => node::run(opts, &prepend("status", rest)),
        "health" => node::run(opts, &prepend("health", rest)),
        "doctor" => node::run(opts, &prepend("doctor", rest)),
        "logs" => node::run(opts, &prepend("logs", rest)),
        "start" => node::run(opts, &prepend("start", rest)),
        "stop" => node::run(opts, &prepend("stop", rest)),
        "restart" => node::run(opts, &prepend("restart", rest)),
        "support-bundle" => node::run(opts, &prepend("support-bundle", rest)),
        "config" => node::run(opts, &prepend("config", rest)),
        "backup" => data::run(opts, &prepend("backup", rest)),
        "restore" => data::run(opts, &prepend("restore", rest)),
        "node-upgrade" | "upgrade" => data::run(opts, &prepend("upgrade", rest)),
        "agents" => workload::run(opts, &prepend("list", rest)),

        // Removed soft-lie / phantom commands — fail closed
        "glue" | "quickstart" | "learn" | "boot" | "why" | "issue" | "fix" | "check"
        | "gate" | "e" | "p" | "t" | "risk" | "pentest" | "threat" | "surveillance"
        | "infra" | "network" | "dns" | "tls" | "chain" | "security" | "system"
        | "registry" | "top" | "stats" | "exec" | "clean" | "bootstrap" | "plugin"
        | "plugins" | "hub" | "app" | "workflow" | "tier" | "llm" | "keys" => {
            Ok(removed(opts, head).emit(opts))
        }

        other => Err(format!(
            "usage: unknown command '{other}'. Run `connectorctl help`."
        )),
    }
}

fn prepend(verb: &str, rest: &[String]) -> Vec<String> {
    let mut v = vec![verb.to_string()];
    v.extend(rest.iter().cloned());
    v
}

fn removed(_opts: &GlobalOpts, name: &str) -> CmdResult {
    CmdResult {
        ok: false,
        command: name.into(),
        exit: ExitCode::Unavailable,
        source: Provenance::host("command registry"),
        data: json!({}),
        warnings: vec![],
        error: Some(format!(
            "command '{name}' removed: no proven Connector endpoint or host mechanism. See `connectorctl help`."
        )),
    }
}

fn namespace_help(opts: &GlobalOpts, ns: &str) -> Result<ExitCode, String> {
    let text = match ns {
        "node" => "node start|stop|restart|status|health|doctor|logs [--follow] [-n N]|support-bundle [--out FILE]|config show",
        "data" => "data backup [--out FILE]|restore <FILE> --yes|upgrade [--from-tarball PATH] [--apply]|storage",
        "workload" => "workload list|show <pid>|deploy <manifest>|start <pid>|stop <pid>|logs <pid>|inspect <pid>",
        "govern" => "govern policy|compliance scorecard|cost <pid>|metrics|events|backends|deploy-verify [linux-kvm|kubernetes]|ecosystem|explain <receipt-id>|cease-proof <agent-pid>",
        "product" => "product install <spec.json>|start|stop|restart|upgrade <spec.json>|rollback|status|diagnose|uninstall [purge]|reconcile|demo governed-agent|task --model <llm> --surface <path|sandbox|dedicated> --purpose <sentence>|providers|compatibility",
        "substrate" => "substrate status|arc posture|svf posture|dal posture|rollup posture|worldline export --agent <pid>",
        "access" => "access status|mode [dev|pilots|production]|activate|pilot list|license status|license tiers",
        "iia" => "iia smoke [--conp]  (CONP catalog + CNP overview; --conp persists CapabilityGrant + actuation)",
        _ => return Err(format!("usage: unknown help topic '{ns}'")),
    };
    Ok(CmdResult {
        ok: true,
        command: format!("help {ns}"),
        exit: ExitCode::Success,
        source: Provenance::host("builtin help"),
        data: human_lines(vec![text.into()]),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

fn version(opts: &GlobalOpts) -> Result<ExitCode, String> {
    let mut data = json!({
        "cli_version": env!("CARGO_PKG_VERSION"),
        "cli_name": "connectorctl",
    });
    let mut warnings = vec![];
    match crate::transport::Client::new(opts) {
        Ok(c) => match c.get_json("/version") {
            Ok(v) => {
                data["node"] = v;
                data["source_route"] = json!("/version");
            }
            Err(e) => warnings.push(e.message()),
        },
        Err(e) => warnings.push(e),
    }
    Ok(CmdResult {
        ok: true,
        command: "version".into(),
        exit: ExitCode::Success,
        source: Provenance::host("cli binary + optional GET /version"),
        data: if opts.output == crate::output::OutputMode::Human {
            let mut lines = vec![format!("connectorctl {}", env!("CARGO_PKG_VERSION"))];
            if let Some(nv) = data.get("node") {
                lines.push(format!("node: {nv}"));
            }
            for w in &warnings {
                lines.push(format!("(node version unavailable: {w})"));
            }
            human_lines(lines)
        } else {
            data
        },
        warnings,
        error: None,
    }
    .emit(opts))
}

fn completion(opts: &GlobalOpts, args: &[String]) -> Result<ExitCode, String> {
    let shell = args.first().map(|s| s.as_str()).unwrap_or("");
    let script = match shell {
        "bash" => BASH,
        "zsh" => ZSH,
        "fish" => FISH,
        _ => {
            return Err("usage: connectorctl completion <bash|zsh|fish>".into());
        }
    };
    Ok(CmdResult {
        ok: true,
        command: format!("completion {shell}"),
        exit: ExitCode::Success,
        source: Provenance::host("builtin completion"),
        data: human_lines(vec![script.into()]),
        warnings: vec![],
        error: None,
    }
    .emit(opts))
}

const BASH: &str = r#"# connectorctl bash completion
_connectorctl() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  local cmds="node data workload govern substrate access version help completion status health doctor logs backup restore support-bundle"
  COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
}
complete -F _connectorctl connectorctl
"#;

const ZSH: &str = r#"#compdef connectorctl
_arguments '1:command:(node data workload govern substrate access version help completion status health doctor logs backup restore support-bundle)'
"#;

const FISH: &str = r#"complete -c connectorctl -f -a 'node data workload govern substrate access version help completion status health doctor logs backup restore support-bundle'
"#;
