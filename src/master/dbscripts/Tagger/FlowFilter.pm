package Tagger::FlowFilter;
use common::sense;
use AddrStoreBuild qw($cfg addr_store_content);

sub perform($$) {
	my ($dbh, $blacklist) = @_;
	# Read the IPset rules and extract addresses
	open my $ipsets, '-|', 'wget', 'https://api.turris.cz/firewall/turris-ipsets', '-q', '-O', '-' or die "Couldn't download ip set rules: $!\n";
	my %data;
	my %ranges;
	while (<$ipsets>) {
		next if /^\s*(#.*|)$/; # Skip comments and empty lines
		next if /^create /; # Creations of sets are not interesting for us
		if (/^add\s+\S+\s+(\S+)/) {
			my ($ip, $port, $range) = ($1, '', '');
			($ip, $port) = ($1, "P$3") if $ip =~ /(.*),(udp|tcp):(\d+)/;
			($ip, $range) = ($1, $2) if $ip =~ /(.*)\/(\d+)/;
			if ($ip =~ /:/) {
				$range = '' if $range == 128;
			} else {
				$range = '' if $range == 32;
			}
			if (length $range) {
				$ranges{"$ip,$range"} = 1;
			} else {
				$data{$port}->{$ip} = 1;
			}
		}
	}
	close $ipsets;
	die "Wget failed with $?" if $?;

	open my $graylist, '-|', 'wget', 'https://www.turris.cz/greylist-data/greylist-latest.csv', '-q', '-O', '-' or die "Couldn't download graylist: $!\n";
	my $header = <$graylist>;
	while (<$graylist>) {
		my ($ip) = split /,/;
		$data{''}->{$ip} = 1;
	}
	close $graylist;
	die "Wget failed with $?" if $?;

	my $add_files = $cfg->val('badips', 'files');
	for my $add_file (split /:/, $add_files) {
		open my $file, '<', $add_file or die "Couldn't read file $add_file: $!\n";
		while (<$file>) {
			chomp;
			$data{''}->{$_} = 1;
		}
	}

	my $fb_stm = $dbh->prepare('SELECT DISTINCT remote FROM fake_blacklist_tmp');
	$fb_stm->execute;
	while (my ($ip) = $fb_stm->fetchrow_array) {
		$data{''}->{$ip} = 1;
	}

	# Drop IP addresses from specific rules if they are in the generic one
	while (my ($port, $ips) = each %data) {
		delete @{$data{$port}}{keys %$blacklist};
		next unless $port;
		# Magic. See perldoc perldata, talk about hash slices.
		delete @{$data{$port}}{keys %{$data{''}}};
	}

	# Combine the filter string
	my $comma;
	my $filter = '|(';
	for my $port (sort keys %data) {
		my $ips = $data{$port};
		next unless %$ips;
		$filter .= $comma;
		$comma = ',';
		my $close;
		if ($port =~ /^(.)(\d+)$/) {
			$filter .= "&($1($2),";
			$close = ')';
		}
		$filter .= 'I(';
		$filter .= join ',', sort keys %$ips;
		$filter .= ')';
		$filter .= $close;
	}
	$filter .= ')';

	my $range_filter;
	my @interesting_remote_ports = (
		21,	# ftp
		22,	# ssh
		23,	# telnet
		25,	# smtp
	#	80,	# http
		109,	# pop2
		110,	# pop3
		123,	# ntp
		143,	# imap
		161,	# snmp
		194,	# irc
	#	443,	# https
		445,	# smb
		465,	# smtps
		587,	# submission
		993,	# imaps
		994,	# ircs
		995,	# pop3s
		1443,	# mssql
		2323,	# telnet-alt
		3306,	# mysql
		3389,	# rdp
		5060,	# sip
		5432,	# postgres
		5900,	# vnc
		7547,	# TR-069 (ISP remote control)
		8767,	# teamspeak
	);
	my $ports = 'P(' . (join ',', @interesting_remote_ports) . ')';
	if (%ranges) {
		$range_filter = "|($ports,D(addresses)," . join ',', map "R($_)", sort keys %ranges;
		$range_filter .= ')';
	} else {
		$range_filter = "|($ports,D(addresses))";
	}

	my %flattened;
	while (my ($port, $ips) = each %data) {
		$port =~ s/^P//;
		@flattened{map {
				my $result = $_;
				if ($port) {
					$result = "[$_]" if /:/;
					$result = "$result:$port";
				}
				$result;
			} keys %$ips} = values %$ips;
	}

	my ($max_epoch, $existing) = addr_store_content('flow_filters', 'filter', 'addresses');

	# Compute symetric differences between previous and current versions
	my %to_delete = %$existing;
	delete @to_delete{keys %flattened}; # Delete everything that was except the things that still are to be
	my %to_add = %flattened;
	delete @to_add{keys %$existing}; # Add everything that shall be but didn't exist before

	my $version = (time / 30) % (2**32); # We won't run it more often than once a minute. Half a minute resolution should be enough to provide security that'll never generate two same versions.

	my $mod = $dbh->prepare("INSERT INTO flow_filters (filter, epoch, version, add, address) VALUES ('addresses', ?, ?, ?, ?)");
	$mod->execute($max_epoch, $version, 1, $_) for keys %to_add;
	$mod->execute($max_epoch, $version, 0, $_) for keys %to_delete;

# Check if the filter is different. If not, just keep the old one.
	my ($cur_filter) = $dbh->selectrow_array("SELECT value FROM config WHERE name = 'filter-diff' AND plugin = 'flow'");
	if ($cur_filter ne $range_filter) {
		$dbh->do("UPDATE config SET value = ? WHERE name = 'filter-diff' AND plugin = 'flow'", undef, $range_filter);
		$dbh->do("UPDATE config SET value = ? WHERE name = 'version' AND plugin = 'flow'", undef, $version);
	}
}

1;
