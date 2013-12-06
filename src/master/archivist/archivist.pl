#!/usr/bin/perl
use common::sense;
use DBI;
use Config::IniFiles;

# First connect to databases
my $cfg = Config::IniFiles->new(-file => $ARGV[0]);

sub connect_db($) {
	my ($kind) = @_;
	my ($host, $db, $user, $passwd) = map { $cfg->val($kind, $_) } qw(host db user passwd);
	return DBI->connect("dbi:Pg:dbname=$db;host=$host", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });
}

my $source = connect_db 'source';
my $destination = connect_db 'destination';
