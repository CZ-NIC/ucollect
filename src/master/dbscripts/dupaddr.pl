#!/usr/bin/perl
#    Ucollect - small utility for real-time analysis of network data
#    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# This script checks the database if there are duplicate addresses (eg. address
# added twice or removed twice) in one of the addr_store tables. Of course it
# considers each store separately (and doesn't consider sequences of
# add-remove-add a problem).
use common::sense;
use DBI;
use Config::IniFiles;

my $cfg = Config::IniFiles->new(-file => $ARGV[0]);
my ($host, $db, $user, $passwd, $port) = map { $cfg->val('db', $_) } qw(host db user passwd port);
my $dbh = DBI->connect("dbi:Pg:dbname=$db;host=$host;port=$port", $user, $passwd, { RaiseError => 1, AutoCommit => 0 });

sub check_table($$) {
	my ($table, $name_column) = @_;
	# Get all names of the stores and their corresponding epochs
	my $stores = $dbh->selectall_hashref("SELECT DISTINCT $name_column, epoch FROM $table", [$name_column, 'epoch']);
	# For each in the above tupple...
	for my $name (sort keys %$stores) {
		my $store = $stores->{$name};
		for my $epoch (sort { $a <=> $b } keys %$store) {
			print "Doing $name/$epoch\n";
			# To track what is active AND when it got there or removed
			my (%added, %removed);
			# Get the content in chronological order and go through them, simulating additions and removals
			my $query = $dbh->prepare("SELECT address, add, version FROM $table WHERE $name_column = ? AND epoch = ? ORDER BY version");
			$query->execute($name, $epoch);
			while (my ($address, $add, $version) = $query->fetchrow) {
				if ($add) {
					print "+ $address $version/$added{$address}\n" if exists $added{$address};
					$added{$address} = $version;
					delete $removed{$address};
				} else {
					print "- $address $version/", ($removed{$address} // "-----"), "\n" unless exists $added{$address};
					$removed{$address} = $version;
					delete $added{$address}
				}
			}
		}
	}
}

check_table 'flow_filters', 'filter';
check_table 'fwup_addresses', 'set';
