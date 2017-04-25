#!/usr/bin/perl
use common::sense;
use DBI;

# Look for libraries also in the same directory as the script lives
use FindBin;
use lib $FindBin::Bin;

use AddrStoreBuild;

my @priv_rex = (
	qr/^192\.168\./,
	qr/^10\./,
	qr/^169\.254\./,
	map {
		my $num = $_;
		qr/^172\.$num\./
	} 16..31
);

# Don't confuse with a blacklist we're building. This is a blacklist for analysis ‒ „ignore these addresses when looking for bad guys“
my $omit_addresses = blacklist_load;

my $dbh = db_connect;

shift @ARGV; # Eat the config file path

my $stm = $dbh->prepare("SELECT server, remote, remote_port, local, local_port, start_time_utc, end_time_utc FROM fake_bad_connections WHERE DATE(COALESCE(end_time_utc, start_time_utc)) = ? ORDER BY server, remote, local");
for my $d (@ARGV) {
	my %files;
	$stm->execute($d);
	LINE:
	while (my ($server, @data) = $stm->fetchrow_array) {
		my $remote = $data[0];
		my $local = $data[2];
		for my $rex (@priv_rex) {
			next LINE if $local =~ $rex;
		}
		next LINE if exists $omit_addresses->{$remote};
		if (not exists $files{$server}) {
			open my $file, '>:utf8', "$server-$d.csv" or die "Couldn't write file '$server-$d.csv': $!\n";
			print $file "remote,remote_port,local,local_port,start,end\n";
			$files{$server} = $file;
		}
		my $file = $files{$server};
		print $file (join ",", @data), "\n";
	}
	close $_ for values %files;
}

# The raw blacklist with everything
my $stm = $dbh->prepare("SELECT server, remote, clients, score, mode FROM fake_blacklist ORDER BY server, remote");
$stm->execute;
open my $file, '>:utf8', "blacklist.csv" or die "Couln't write the blacklist file: $!\n";
print $file "server,remote,clients,score,mode\n";
while (my @data = $stm->fetchrow_array) {
	my $remote = $data[1];
	next if exists $omit_addresses->{$remote};
	print $file (join ",", @data), "\n";
}
close $file;
$dbh->rollback;
