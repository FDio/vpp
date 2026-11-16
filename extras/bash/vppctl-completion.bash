# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion
#
# Bash completion for vppctl. The candidates come from the running VPP
# ('test cli complete'), so they always match the commands and the live state
# (interface names, graph nodes, ...) of the VPP instance being talked to.
#
#   source extras/bash/vppctl-completion.bash
#   vppctl set interface state <TAB>
#
# Note: bash splits unquoted '|' into a separate command, to complete output
# filters quote them: vppctl show interface '|' <TAB>

_vppctl_complete()
{
    local i=1 sock=() words line out cur="${COMP_WORDS[COMP_CWORD]}"

    while [[ $i -lt $COMP_CWORD && "${COMP_WORDS[i]}" == -* ]]; do
        if [[ "${COMP_WORDS[i]}" == -s ]]; then
            sock=(-s "${COMP_WORDS[i+1]}")
            ((i++))
        fi
        ((i++))
    done

    words="${COMP_WORDS[*]:i:COMP_CWORD-i}"
    line="${words:+$words }$cur"

    out=$(vppctl "${sock[@]}" test cli complete "\"$line\"" 2>/dev/null) || return
    COMPREPLY=($(compgen -W "$(cut -f1 <<<"$out")" -- "$cur"))
}

complete -F _vppctl_complete vppctl
