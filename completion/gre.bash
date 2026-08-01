# bash completion for the gre command (gre-manager)
# https://github.com/aibedini/gre-manager

_gre() {
    local cur cmds
    cur="${COMP_WORDS[COMP_CWORD]}"
    COMPREPLY=()

    if (( COMP_CWORD == 1 )); then
        cmds="node iran iran-setup doctor export import watchdog status update purge --status --apply --stop --version --help"
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        node)
            if (( COMP_CWORD == 2 )); then
                COMPREPLY=( $(compgen -W "list add remove" -- "$cur") )
            elif (( COMP_CWORD >= 3 )); then
                COMPREPLY=( $(compgen -W "--name --ip --idx --key --subnet-base --yes --json" -- "$cur") )
            fi
            ;;
        iran)
            if (( COMP_CWORD == 2 )); then
                COMPREPLY=( $(compgen -W "peer" -- "$cur") )
            elif (( COMP_CWORD == 3 )); then
                COMPREPLY=( $(compgen -W "list add remove apply" -- "$cur") )
            elif (( COMP_CWORD >= 4 )); then
                case "${COMP_WORDS[3]}" in
                    add)
                        COMPREPLY=( $(compgen -W "--name --foreign-ip --iran-ip --subnet-base --idx --key --wan --tcp-ports --udp-ports --mss-clamp --yes" -- "$cur") )
                        ;;
                    remove|apply)
                        COMPREPLY=( $(compgen -W "--name --yes" -- "$cur") )
                        ;;
                    list)
                        COMPREPLY=( $(compgen -W "--json" -- "$cur") )
                        ;;
                esac
            fi
            ;;
        iran-setup)
            COMPREPLY=( $(compgen -W "--foreign-ip --iran-ip --name --idx --key --subnet-base --wan --tcp-ports --udp-ports --mss-clamp --downtime --yes" -- "$cur") )
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
