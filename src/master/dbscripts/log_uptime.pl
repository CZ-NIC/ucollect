#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;
use Data::Dumper;
use DateTime::Duration;
use List::Util qw(sum);

my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
shift @ARGV;
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $column = $cfg->val('activities', 'time_column') // 'timestamp';
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

my $sub_query;
$sub_query = " AND clients.name IN (" . (join ', ', map "%", @ARGV) . ")" if (@ARGV);
my $query = "SELECT date_part('epoch', $column), clients.name, activity_types.name FROM activities JOIN clients ON clients.id = activities.client JOIN activity_types ON activity_types.id = activities.activity WHERE$sub_query activity_types.name IN ('login', 'logout') ORDER BY clients.name, $column";

my $compiled = $dbh->prepare($query);
$compiled->execute(@ARGV);

my ($last_client, $last_login);
my @client;
my @total;

sub client_push($) {
	push @client, $_[0] - $last_login if $last_login;
}

my $epoch = DateTime->from_epoch(epoch => 0);

sub form($@) {
	my ($client, @data) = @_;
	return unless @data;
	@data = sort { $a <=> $b } @data;
	my ($min, $max, $avg, $mean) = map {
		my @d = (DateTime->from_epoch(epoch => $_) - $epoch)->in_units(qw(days hours));
		sprintf "%2ddays %2dhours", @d;
	} map {
		$_->(@data)
	} sub { $_[0] }, sub { $_[-1] }, sub {
		(sum @_) / (scalar @_);
	}, sub {
		($_[@_ / 2] + $_[(@_ - 1) / 2]) / 2;
	};
	print "$client\t$min\t$max\t$avg\t$mean\n";
}

sub client_process() {
	client_push time;
	form $last_client, @client;
	push @total, @client;
	@client = ();
}

while (my ($time, $client, $action) = $compiled->fetchrow_array) {
	if ($client ne $last_client) {
		client_process;
		$last_client = $client;
		undef $last_login;
	}
	client_push $time;
	undef $last_login;
	$last_login = $time if $action eq 'login';
}

client_process;

form "Total\t\t", @total;

$dbh->rollback;
