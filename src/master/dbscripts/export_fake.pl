#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;

my @priv_rex = (
	qr/^192\.168\./,
	qr/^10\./,
	qr/^169\.254\./,
	map {
		my $num = $_;
		qr/^172\.$num\./
	} 16..31
);

my $cfg = Config::IniFiles->new(-file => $ARGV[0]) or die "Couldn't read config file $ARGV[0]: @Config::IniFiles::errors\n";
shift @ARGV;
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });
my $stm = $dbh->prepare("SELECT server, remote, remote_port, local, local_port, start_time_utc, end_time_utc FROM fake_bad_connections WHERE DATE(end_time_utc) = ? ORDER BY server, remote, local");
for my $d (@ARGV) {
	my %files;
	$stm->execute($d);
	LINE:
	while (my ($server, @data) = $stm->fetchrow_array) {
		my $local = $data[2];
		for my $rex (@priv_rex) {
			next LINE if $local =~ $rex;
		}
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
$dbh->rollback;
