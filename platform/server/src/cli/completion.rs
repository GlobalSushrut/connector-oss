//! Shell Completion for connectorctl
//!
//! Generates shell completion scripts for bash, zsh, and fish.

/// Shell type
#[derive(Debug, Clone, Copy)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }
}

/// Generate completion script for the given shell
pub fn generate_completion(shell: Shell) -> String {
    match shell {
        Shell::Bash => generate_bash(),
        Shell::Zsh => generate_zsh(),
        Shell::Fish => generate_fish(),
    }
}

fn generate_bash() -> String {
    r#"# connectorctl bash completion
# Install: connectorctl completion bash > /etc/bash_completion.d/connectorctl
#      or: connectorctl completion bash >> ~/.bashrc

_connectorctl() {
    local cur prev words cword
    _init_completion || return

    local commands="start stop restart status health doctor logs agents inspect deploy bootstrap backup restore config version help"
    local config_cmds="validate show"

    case "${prev}" in
        connectorctl)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return
            ;;
        start|restart)
            COMPREPLY=($(compgen -W "--foreground -f" -- "${cur}"))
            return
            ;;
        doctor)
            COMPREPLY=($(compgen -W "--verbose -v" -- "${cur}"))
            return
            ;;
        logs)
            COMPREPLY=($(compgen -W "--follow -f --lines -n" -- "${cur}"))
            return
            ;;
        deploy)
            COMPREPLY=($(compgen -W "--dry-run" -- "${cur}"))
            _filedir yaml
            return
            ;;
        bootstrap)
            COMPREPLY=($(compgen -W "--apply" -- "${cur}"))
            return
            ;;
        backup)
            COMPREPLY=($(compgen -W "--output -o" -- "${cur}"))
            return
            ;;
        restore)
            _filedir 'tar.gz'
            return
            ;;
        config)
            COMPREPLY=($(compgen -W "${config_cmds}" -- "${cur}"))
            return
            ;;
        inspect)
            # Could complete agent PIDs from API
            return
            ;;
        help)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return
            ;;
        -o|--output)
            _filedir
            return
            ;;
        -n|--lines)
            COMPREPLY=($(compgen -W "10 50 100 500" -- "${cur}"))
            return
            ;;
    esac

    # Handle options for current command
    case "${words[1]}" in
        start|restart)
            COMPREPLY=($(compgen -W "--foreground -f" -- "${cur}"))
            ;;
        doctor)
            COMPREPLY=($(compgen -W "--verbose -v" -- "${cur}"))
            ;;
        logs)
            COMPREPLY=($(compgen -W "--follow -f --lines -n" -- "${cur}"))
            ;;
        deploy)
            if [[ "${cur}" == -* ]]; then
                COMPREPLY=($(compgen -W "--dry-run" -- "${cur}"))
            else
                _filedir yaml
            fi
            ;;
        bootstrap)
            COMPREPLY=($(compgen -W "--apply" -- "${cur}"))
            ;;
        backup)
            COMPREPLY=($(compgen -W "--output -o" -- "${cur}"))
            ;;
    esac
}

complete -F _connectorctl connectorctl
"#.to_string()
}

fn generate_zsh() -> String {
    r#"#compdef connectorctl
# connectorctl zsh completion
# Install: connectorctl completion zsh > ~/.zsh/completions/_connectorctl
#      or: connectorctl completion zsh > /usr/local/share/zsh/site-functions/_connectorctl

_connectorctl() {
    local -a commands
    commands=(
        'start:Start the Connector Node'
        'stop:Stop the Connector Node'
        'restart:Restart the Connector Node'
        'status:Show node status'
        'health:Quick health check'
        'doctor:Full diagnostic report'
        'logs:View node logs'
        'agents:List running agents'
        'inspect:Inspect an agent'
        'deploy:Deploy an agent manifest'
        'bootstrap:Migrate legacy env secrets into vault'
        'backup:Create a backup'
        'restore:Restore from backup'
        'config:Configuration commands'
        'version:Show version'
        'help:Show help'
    )

    local -a config_commands
    config_commands=(
        'validate:Check configuration for errors'
        'show:Display current configuration'
    )

    _arguments -C \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'connectorctl command' commands
            ;;
        args)
            case $words[1] in
                start|restart)
                    _arguments \
                        '(-f --foreground)'{-f,--foreground}'[Run in foreground]'
                    ;;
                doctor)
                    _arguments \
                        '(-v --verbose)'{-v,--verbose}'[Show verbose output]'
                    ;;
                logs)
                    _arguments \
                        '(-f --follow)'{-f,--follow}'[Follow log output]' \
                        '(-n --lines)'{-n,--lines}'[Number of lines]:lines:(10 50 100 500)'
                    ;;
                deploy)
                    _arguments \
                        '--dry-run[Validate without deploying]' \
                        '*:manifest file:_files -g "*.yaml *.yml"'
                    ;;
                bootstrap)
                    _arguments '--apply[Write secrets to vault]'
                    ;;
                backup)
                    _arguments \
                        '(-o --output)'{-o,--output}'[Output file]:file:_files'
                    ;;
                restore)
                    _arguments \
                        '*:backup file:_files -g "*.tar.gz"'
                    ;;
                config)
                    _describe -t config_commands 'config command' config_commands
                    ;;
                inspect)
                    _arguments '*:agent PID:'
                    ;;
                help)
                    _describe -t commands 'command' commands
                    ;;
            esac
            ;;
    esac
}

_connectorctl "$@"
"#.to_string()
}

fn generate_fish() -> String {
    r#"# connectorctl fish completion
# Install: connectorctl completion fish > ~/.config/fish/completions/connectorctl.fish

# Disable file completion by default
complete -c connectorctl -f

# Commands
complete -c connectorctl -n "__fish_use_subcommand" -a start -d "Start the Connector Node"
complete -c connectorctl -n "__fish_use_subcommand" -a stop -d "Stop the Connector Node"
complete -c connectorctl -n "__fish_use_subcommand" -a restart -d "Restart the Connector Node"
complete -c connectorctl -n "__fish_use_subcommand" -a status -d "Show node status"
complete -c connectorctl -n "__fish_use_subcommand" -a health -d "Quick health check"
complete -c connectorctl -n "__fish_use_subcommand" -a doctor -d "Full diagnostic report"
complete -c connectorctl -n "__fish_use_subcommand" -a logs -d "View node logs"
complete -c connectorctl -n "__fish_use_subcommand" -a agents -d "List running agents"
complete -c connectorctl -n "__fish_use_subcommand" -a inspect -d "Inspect an agent"
complete -c connectorctl -n "__fish_use_subcommand" -a deploy -d "Deploy an agent manifest"
complete -c connectorctl -n "__fish_use_subcommand" -a bootstrap -d "Migrate legacy env secrets into vault"
complete -c connectorctl -n "__fish_use_subcommand" -a backup -d "Create a backup"
complete -c connectorctl -n "__fish_use_subcommand" -a restore -d "Restore from backup"
complete -c connectorctl -n "__fish_use_subcommand" -a config -d "Configuration commands"
complete -c connectorctl -n "__fish_use_subcommand" -a version -d "Show version"
complete -c connectorctl -n "__fish_use_subcommand" -a help -d "Show help"
complete -c connectorctl -n "__fish_use_subcommand" -a completion -d "Generate shell completion"

# start options
complete -c connectorctl -n "__fish_seen_subcommand_from start" -s f -l foreground -d "Run in foreground"

# restart options
complete -c connectorctl -n "__fish_seen_subcommand_from restart" -s f -l foreground -d "Run in foreground"

# doctor options
complete -c connectorctl -n "__fish_seen_subcommand_from doctor" -s v -l verbose -d "Show verbose output"

# logs options
complete -c connectorctl -n "__fish_seen_subcommand_from logs" -s f -l follow -d "Follow log output"
complete -c connectorctl -n "__fish_seen_subcommand_from logs" -s n -l lines -d "Number of lines" -xa "10 50 100 500"

# deploy options
complete -c connectorctl -n "__fish_seen_subcommand_from deploy" -l dry-run -d "Validate without deploying"
complete -c connectorctl -n "__fish_seen_subcommand_from deploy" -F -d "Manifest file"

# bootstrap
complete -c connectorctl -n "__fish_seen_subcommand_from bootstrap" -l apply -d "Write secrets to vault"

# backup options
complete -c connectorctl -n "__fish_seen_subcommand_from backup" -s o -l output -d "Output file" -rF

# restore - file completion
complete -c connectorctl -n "__fish_seen_subcommand_from restore" -F -d "Backup file"

# config subcommands
complete -c connectorctl -n "__fish_seen_subcommand_from config" -a validate -d "Check configuration"
complete -c connectorctl -n "__fish_seen_subcommand_from config" -a show -d "Show configuration"

# help - complete with commands
complete -c connectorctl -n "__fish_seen_subcommand_from help" -a "start stop restart status health doctor logs agents inspect deploy bootstrap backup restore config version"

# completion subcommand
complete -c connectorctl -n "__fish_seen_subcommand_from completion" -a "bash zsh fish" -d "Shell type"
"#.to_string()
}

/// Print installation instructions
pub fn print_install_instructions(shell: Shell) {
    match shell {
        Shell::Bash => {
            println!("# Bash completion installation:");
            println!();
            println!("# System-wide (requires root):");
            println!("connectorctl completion bash | sudo tee /etc/bash_completion.d/connectorctl > /dev/null");
            println!();
            println!("# User only:");
            println!("connectorctl completion bash >> ~/.bashrc");
            println!("source ~/.bashrc");
        }
        Shell::Zsh => {
            println!("# Zsh completion installation:");
            println!();
            println!("# Create completions directory if needed:");
            println!("mkdir -p ~/.zsh/completions");
            println!();
            println!("# Install completion:");
            println!("connectorctl completion zsh > ~/.zsh/completions/_connectorctl");
            println!();
            println!("# Add to ~/.zshrc:");
            println!("fpath=(~/.zsh/completions $fpath)");
            println!("autoload -Uz compinit && compinit");
        }
        Shell::Fish => {
            println!("# Fish completion installation:");
            println!();
            println!("connectorctl completion fish > ~/.config/fish/completions/connectorctl.fish");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_from_str() {
        assert!(matches!(Shell::from_str("bash"), Some(Shell::Bash)));
        assert!(matches!(Shell::from_str("zsh"), Some(Shell::Zsh)));
        assert!(matches!(Shell::from_str("fish"), Some(Shell::Fish)));
        assert!(Shell::from_str("unknown").is_none());
    }

    #[test]
    fn test_bash_completion() {
        let script = generate_bash();
        assert!(script.contains("_connectorctl"));
        assert!(script.contains("complete -F"));
    }

    #[test]
    fn test_zsh_completion() {
        let script = generate_zsh();
        assert!(script.contains("#compdef connectorctl"));
        assert!(script.contains("_connectorctl"));
    }

    #[test]
    fn test_fish_completion() {
        let script = generate_fish();
        assert!(script.contains("complete -c connectorctl"));
    }
}
