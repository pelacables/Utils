# Utils
=======

## kill_orphans

This script finds  orphan processes in a GNU/Linux host.
It can list the processes, kill them or send aa detailed e-mail to the owner of the process (the e-mail is asked to a LDAP server).

 Usage:
    kill_orphan [OPTION] 

            --help,-h       : display this help
            --man           : show man 
            --mode          : [informer|assassin|list]
                            - informer: send e-mail to user which have orphan processes
                            - assassin: kill orphan processes
                            - list: sho the list of orphan processes in STDOUT


            simple example:         kill_orphan --mode assassin

    *It automatically logs in /var/log/orphan_processes.log
