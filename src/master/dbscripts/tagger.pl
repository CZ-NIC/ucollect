#!/usr/bin/perl

# Look for libraries also in the same directory as the script lives
use FindBin;
use lib $FindBin::Bin;

use AddrStoreBuild;
#use Tagger::Flows;
use Tagger::FlowFilter;
use Tagger::FwUp;
use Getopt::Long;
use Data::Dumper;

# Don't start parallel instances of the script
single_instance '/tmp/tagger.lock';

my @flows;
GetOptions
	"flows=s"	=> \@flows
or die "Error in command line arguments\n";

my $dbh = db_connect;

my $blacklist = blacklist_load;

# Prepare a shared precomputed blacklist, so all the loggers can reuse the result of the rather expensive query
$dbh->do('CREATE TEMPORARY TABLE fake_blacklist_tmp AS (SELECT remote, server, mode FROM fake_blacklist) WITH DATA');
$dbh->do('ANALYZE fake_blacklist_tmp');
print "Prepared the fake blacklist\n";

# Prepare the tags to be used for tagging the flows
#my $flow_tags = Tagger::Flows::prepare_tags($dbh, @flows);

Tagger::FlowFilter::perform($dbh, $blacklist);
print "Stored flow filters\n";

Tagger::FwUp::perform($dbh, $blacklist);
print "Stored FWUp filters\n";

# We no longer need the temporary table, commit will kill it. Also, commit the filters and sets.
$dbh->commit;

#Tagger::Flows::perform($dbh, $flow_tags);
