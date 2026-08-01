# bash completion for the gre command (gre-manager)
# https://github.com/aibedini/gre-manager

_gre() {
    local cur cmds
    cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=()

    if (( COMP_CWORD == 1 )); then
        cmds="node iran-setup doctor export import watchdog status update purge --status --apply --stop --version --help"
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        node)
            if (( COMP_CWORD == 2 )); then
                COMPREPLY=( $(compgen -W "list add remove" -- "$cur") )
            elif (( COMP_CWORD >= 3 )); then
                COMPREPLY=( $(compgen -W "--name --ip --idx --key --yes --json" -- "$cur") )
            fi
            ;;
        iran-setup)
            COMPREPLY=( $(compgen -W "--foreign-ip --iran-ip --name --idx --key --wan --tcp-ports --udp-ports --mss-clamp --downtime --yes" -- "$cur") )
            ;;
        watchdog)
            COMPREPLY=( $(compgen -W "enable disable status interval" -- "$cur") )
            ;;
        status|--status)
            COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            ;;
        import)
            COMPREPLY=( $(compgen -f -X '!*.tar.gz' -- "$cur") )
            ;;
    esac
    return 0
}

complete -F _gre gre
