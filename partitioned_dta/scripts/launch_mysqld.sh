#!/bin/bash

pin=""


function usage() {
    echo "$0 [OPTIONS]"
    echo "  -dta    Launch using always-on DTA"
    echo "  -pdta   Launch using partitioned DTA"
    echo "  -pin    Launch using Pin"
    echo "  -h      Print this message"
    exit 1
}

until [ -z "$1" ]; do
    case "$1" in
    -dta)
        pin="pin -follow_execv -t partitioned_dta.so -p 0 -fslist tracklist.conf --"
        ;;
    -pdta)
        pin="pin -follow_execv -t partitioned_dta.so -fslist tracklist.conf --"
        ;;
    -pin)
        pin="pin -follow_execv --"
        ;;
    -h)
        usage
        ;;
    esac
    shift
done

mysql_home="/home/porto"
cmdline="/usr/libexec/mysqld --console --datadir=$mysql_home/var/lib/mysql/ --pid-file=$mysql_home/var/run/mysql/mysql.pid --socket=$mysql_home/var/run/mysql/mysql.sock"


$pin $cmdline

