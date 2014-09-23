# Utils
=======

## kill_orphans

Usage:
    kill_orphan [OPTION] INPUT_FILE

            --help,-h       : display this help
            --man           : show man 
            --mode          : [informer|assassin|list]
                            - informer: send e-mail to user which have orphan processes
                            - assassin: kill orphan processes
                            - list: sho the list of orphan processes in STDOUT


            simple example:         kill_orphan --mode assassin

    *It automatically logs in /var/log/orphan_processes.log
