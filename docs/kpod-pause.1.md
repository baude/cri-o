% kpod(1) kpod-pause - Pause all the processes in one or more containers
% Brent Baude
# kpod-pause "1" "September 2017" "kpod"

## NAME
kpod pause - Pause all the processes in one or more containers

## SYNOPSIS
**kpod pause CONTAINER [...]**

## DESCRIPTION
Pauses all the processes in one or more containers.  You may use container IDs or names as input.

## EXAMPLE

kpod pause mywebserver

kpod pause 860a4b23

## SEE ALSO
kpod(1), kpod-unpause(1)

## HISTORY
September 2018, Originally compiled by Brent Baude <bbaude@redhat.com>
