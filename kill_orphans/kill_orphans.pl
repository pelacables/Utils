#!/usr/bin/perl

#################### Modificación de Killbatchorpans #######################################
# Procesos con id > 500 corriendo en nodos shared con time > queue time se deberían matar. #
# En nodos dedicados, reportar los que llevan más de X días y/o buscar PPID a ver is es    #
# un sge_shepherd									   #
############################################################################################

use strict;

use constant LOG_DIR    => '/var/log/';
use constant LOG_FILE   => 'orphan_processes.log';
use constant PIDDIR     => LOG_DIR;

use POSIX;
use Getopt::Long;
use Proc::ProcessTable;
use Log::Dispatch;
use Log::Dispatch::File;
use Data::Dumper;
use Array::Unique;
use Net::LDAP;
use Pod::Usage;
use POSIX 'strftime';


my ($help,$man,$mode);
GetOptions (
        'version|V'     => sub { VersionMessage() ; exit 0},
        'help|h'        => \$help,
        'man'           => \$man,
	'mode=s'	=> \$mode,
) or  pod2usage(2);

pod2usage(1) if $help;
pod2usage(-verbose => 2) if $man;
pod2usage(1) if ($mode !~ /assassin|informer|list/);

# Logging
my $hostname=`hostname -f`;
chop $hostname;
my $log = Log::Dispatch->new();
$log->add(
	Log::Dispatch::File->new(
	callbacks => sub { my %h=@_; return scalar localtime(time)." ".$hostname." $0\[$$]: ".$h{message}."\n"; },
	mode      => 'append',
	name      => 'logfile',
	min_level => 'info',
	filename  => LOG_DIR."/".LOG_FILE,
	)
);

# Configurable values:
# Processes
# Exceptions:
my @exception=qw(sshd dbus encfs SCREEN ssh-agent dropbox);
# LDAP:
my $ldap_server='allende.crg.es';
my $ldap_bind_user='crgcomu@crg';
my $ldap_bind_password='crgcomu';
# E-mail
# Default e-mail address (and also for From:)
my $from= "arnau.bria\@crg.es";
# Default Subject:
# Default e-mail content :
my $template="You are getting this e-mail because some of your processes are running in $hostname without control.\nPlease, refer to http://www.linux.crg.es/index.php/FAQ#Why_am_I_getting_an_e-mail_about_orphan_processes_in_ant-login_nodes.3F for futher details.\nThe list of orphan PIDs:\n"; 


$log->info("Looking for Orphan processes. Running in \'$mode\' mode ");

# Create a new process table object
my ($pt) = new Proc::ProcessTable;

# Initialize your process table hash
my $pt_hash;
# Initialize your Orphan process table hash
my $orphan_process;

# Get the fields that your architecture supports
my (@fields) = $pt->fields;

# Outer loop for each process id
foreach my $proc ( @{$pt->table} ) {
	# Inner loop for each field within the process id
	for my $field (@fields) {
	# Add the field to the hash
		$pt_hash->{$proc->pid}->{$field} = $proc->$field();
	}
}

sub is_not_exception () {
	foreach (@exception) {
		if ($_[0] =~ $_){
			return 0;	
		}
	}
	return 1;
}

sub look_for_orphan () {
	#now the hash %pt_hash has all the proc info. Let process it, we'll save all orphan process in orphan_process hash:
		foreach my $pid (keys (%$pt_hash)) {
		# We skip processes with uid < 500
		next if ($pt_hash->{$pid}->{uid} < '500' ) ;
		# Some human readable vars:
		my $PPID_UID=$pt_hash->{$pt_hash->{$pid}->{ppid}}->{uid};
		my $cmndline=$pt_hash->{$pid}->{cmndline};
		my $orph_pid=$pid;
		my $orphan=1;
		while ($orphan) {
			# get pid's ppid
			$log->debug("PID: $orph_pid PPID: $pt_hash->{$orph_pid}->{ppid}, UID: $pt_hash->{$pt_hash->{$orph_pid}->{ppid}}->{uid}, EXEC: $pt_hash->{$orph_pid}->{cmndline} , PEXEC: $pt_hash->{$pt_hash->{$orph_pid}->{ppid}}->{cmndline}");
			if (($PPID_UID  ==  '0' ) && (&is_not_exception ($cmndline))) {
				my $user=getpwuid($pt_hash->{$orph_pid}->{uid});
				$orphan_process->{$user}->{PIDs}->{$orph_pid}->{cmd}=$cmndline;
				$orphan_process->{$user}->{PIDs}->{$orph_pid}->{date}=strftime('%d/%m/%Y', localtime($pt_hash->{$pid}->{start}));
				$log->info("Found PID: $orph_pid with command $cmndline from user:  $user");
				# It's an orphan process:
				$orphan=0;
			}else{
				# new proc pid's ppid
				# Check if 
				if (defined $pt_hash->{$pt_hash->{$orph_pid}->{ppid}}->{pid}) {
					$orph_pid=$pt_hash->{$pt_hash->{$orph_pid}->{ppid}}->{pid};
				}else{
					# Strange condition, but we break the bucle...
					$orphan=0;
				} 
			}
		}
	}
}


sub look_for_email () {
	# Let's ask for user e-mail. We must contact LDAP
	# Connect
	my $ldap = Net::LDAP->new ( "$ldap_server" ) or die "$@";
	my $ldap_mesg = $ldap->bind ( "$ldap_bind_user", password => "$ldap_bind_password", version => 3 );
	$ldap_mesg = $ldap->search( # perform a search
                        base   => "OU=Programes,DC=crg,DC=es",
                        filter => "sAMAccountName=abria",
			attrs	=> ['sAMAccountName','mail'],
                      );
	$ldap_mesg->code && die $ldap_mesg->error;
	# Parse all uid/email and add e-mail to orhpan_process hash:
		foreach my $entry ( $ldap_mesg->entries ) {
			my $sAMAccountName=$entry->get_value("sAMAccountName");
			if (exists $orphan_process->{$sAMAccountName}){
				$orphan_process->{$sAMAccountName}->{mail}=$entry->get_value("mail");
			}
		}
	$ldap->unbind;
	# OK, all the info saved in hash orphan_process.
}


$log->info("Parsing process table...\n");
&look_for_orphan ();

if ($mode == 'informer'){
	$log->info("Looking for people's e-mail...\n");
	&look_for_email ();
}

# Now will all the info in our hash 'orphan_process' we check the mode: assassin/informer/list
for my $orphan_user (keys %$orphan_process) {
	if ($mode == 'informer'){
        	my $subject="Orphan processes from $orphan_user in $hostname";
		my $to;
		if (defined $orphan_process->{$orphan_user}->{mail}) {
       			$to=$orphan_process->{$orphan_user}->{mail};
		}else{
			$log->info("WARNING: $orphan_user has no e-mail\n");
       			$to=$from;
		}
		$log->debug("Sending e-mail to user: $orphan_user with e-mail: $to");
       		open(MAIL, "|/usr/sbin/sendmail -t");
		print MAIL "To: $to\n";
		print MAIL "Subject: $subject\n";
		print MAIL "From: $from\n";
		print MAIL "Content-type: text/plain\n\n";
		print MAIL $template;
	}
	# Get the list of PIDs and print/e-mail/kill:
	for my $PID (keys %{$orphan_process->{$orphan_user}->{PIDs}}) {	
		$log->debug("PID: $PID, command: $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{cmd} belonging to $orphan_user (started on $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{date})");
		if ($mode eq 'informer') {
			print MAIL "PID: $PID, command: $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{cmd} (started on $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{date})\n";
		}
		elsif ($mode eq 'list'){
			print "PID: $PID, command: $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{cmd} belonging to $orphan_user (started on $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{date})\n";
		}
		elsif ($mode eq 'assassin') {
			$log->info("Killing PID: $PID (command $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{cmd}) belonging to $orphan_user");
			print "kill -9 $PID (Killing PID: $PID with command $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{cmd}) (started on $orphan_process->{$orphan_user}->{PIDs}->{$PID}->{date})\n";
		}
	}
	if ($mode == 'informer'){
		close(MAIL);
	}
}
#print Dumper \$orphan_process;
sub VersionMessage {
        print "version: 0.0.1\n\n";
}

__END__
#." Manpage for kill_orphan
#." Contact arnaubria at gmail dot com to fix bugs or typos.
.TH man 1 "23 Sep 2014" "0.0.1" "kill_orphan an page"

=pod


=head1 NAME

kill_orphan - Kill orphan processess

=head1 SYNOPSIS

B<kill_orphan>
[OPTION] INPUT_FILE

        --help,-h       : display this help
        --man           : show man 
        --mode		: [informer|assassin|list]
                        - informer: send e-mail to user which have orphan processes
                        - assassin: kill orphan processes
                        - list: sho the list of orphan processes in STDOUT


        simple example:         kill_orphan --mode assassin

*It automatically logs in /var/log/orphan_processes.log

=head1 DESCRIPTION

This script is designed to detect orphan processes in any host.

=head2 CONFIG OPTIONS

Starting at line 53 (aprox) you'll find some values that can/must be changed:

# Configurable values:
# Processes
# Exceptions:
my @exception=qw(sshd dbus encfs SCREEN ssh-agent dropbox);
# LDAP:
my $ldap_server='allende.crg.es';
my $ldap_bind_user='crgcomu@crg';
my $ldap_bind_password='crgcomu';
# E-mail
# Default e-mail address (and also for From:)
my $from= "arnau.bria\@crg.es";
# Default Subject:
# Default e-mail content :
my $template="You are getting this e-mail because some of your processes are running in $hostname without control.\nPlease, refer to http://www.linux.crg.es/index.php/FAQ#Why_am_I_getting_an_e-mail_about_orphan_processes_in_ant-login_nodes.3F for futher details.\nThe list of orphan PIDs:\n"; 

=head2 LOG
It automatically logs in /var/log/orphan_processes.log
=cut


