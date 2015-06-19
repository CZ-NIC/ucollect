#!/usr/bin/perl
use common::sense;
use utf8;
use Getopt::Long;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::Util qw(run_cmd);
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use Data::Dumper;

my ($verbose, $base_url, @list_names, @packages);

GetOptions
	verbose => \$verbose,
	'list=s' => \@list_names,
	'url=s' => \$base_url,
	'package=s' => \@packages
or die "Bad params\n";

die "No URL given\n" unless $base_url;
die "No list name given\n" unless @list_names;
die "No packages allowed\n" unless @packages;

sub dbg(@) {
	print STDERR "DBG: ", @_ if $verbose;
}

my $unpack_cmd = dirname($0) . "/pkg-unpack";
my $tmp_dir = tempdir(CLEANUP => 1);
dbg "Using $unpack_cmd to unpack to $tmp_dir\n";
my %packages = map { $_ => 1 } @packages;
my %seen;
my @hashes;

my @condvars;
my $err;
my $unpack_limit = 10;
my @unpack_queue;

sub cv_get() {
	my $cv = AnyEvent->condvar;
	push @condvars, $cv;
	return $cv;
}

sub process_package($$$$) {
	my ($name, $version, $body, $cv) = @_;
	my $output;
	dbg "Unpacking $name-$version\n";
	my $finished = run_cmd [$unpack_cmd, "$tmp_dir/$name/$version", $name, $version],
		'>' => \$output,
		'<' => \$body,
		close_all => 1;
	$finished->cb(sub {
		my $ecode = shift->recv;
		if ($ecode) {
			warn "Failed to unpack $name-$version: $ecode\n";
			$err = 1;
		} else {
			dbg "Unpacked $name\n";
			my ($hash, $libname) = split /\s+/, $output;
			push @hashes, {
				name => $name,
				libname => $libname,
				version => $version,
				hash => $hash
			};
		}
		$cv->send;
		$unpack_limit ++;
		&check_unpack_queue();
	});
}

sub check_unpack_queue() {
	return dbg "Nothing in the unpack queue\n" unless @unpack_queue;
	return dbg "No free unpack slots\n" unless $unpack_limit;
	$unpack_limit --;
	my $params = shift @unpack_queue;
	process_package $params->{name}, $params->{version}, $params->{body}, $params->{cv};
}

sub handle_package($$$) {
	my ($name, $version, $body) = @_;
	push @unpack_queue, {
		name => $name,
		version => $version,
		body => $body,
		cv => cv_get,
	};
	check_unpack_queue;
}

sub get_pkg($$) {
	my ($name, $version) = @_;
	my $full_url = "$base_url/packages/$name-$version.ipk";
	return dbg "The URL $full_url has already been seen\n" if $seen{$full_url};
	$seen{$full_url} = 1;
	dbg "Downloading $full_url\n";
	my $cv = cv_get;
	http_get $full_url, tls_ctx => "high", sub {
		my ($body, $hdrs) = @_;
		if (defined $body and $hdrs->{Status} == 200) {
			handle_package $name, $version, $body;
		} else {
			warn "Couldn't download $full_url: $hdrs->{Status} $hdrs->{Reason}\n";
			$err = 1;
		}
		$cv->send;
	};
}

sub handle_list($$) {
	my ($name, $list) = @_;
	open my $input, '<:utf8', \$list or die "Error reading list: $!\n";
	my $have_plugin;
	while (<$input>) {
		chomp;
		my ($pname, $version, $flags, $hash) = split;
		next if $flags =~ /R/; # These are to be removed, so ignore them
		get_pkg $pname, $version if ($packages{$pname});
		$have_plugin = 1;
	}
	unless ($have_plugin) {
		warn "No plugin found in $name\n";
		$err = 1;
	}
}

sub get_list($) {
	my ($name) = @_;
	my $full_url = "$base_url/lists/$name";
	dbg "Downloading list $name from $full_url\n";
	my $cv = cv_get;
	http_get $full_url, tls_ctx => "high", sub {
		my ($body, $hdrs) = @_;
		if (defined $body and $hdrs->{Status} == 200) {
			dbg "Downloaded list $name\n";
			handle_list $name, $body;
		} else {
			warn "Failed to download list $name: $hdrs->{Status} $hdrs->{Reason}\n";
			$err = 1;
		}
		$cv->send;
	};
}

get_list $_ for @list_names;

# Wait for all asynchronous tasks (even the ones that appear during other tasks)
while (@condvars) {
	my $cv = shift @condvars;
	$cv->recv;
}

my $output;
open my $out, '>:utf8', \$output or die "Couldn't format output: $!\n";
print $out "BEGIN;\n";
for my $hash (@hashes) {
	my $name = $hash->{name};
	$name =~ s/^ucollect-//;
	my $act = $name;
	$name =~ s/^(.)/uc($1)/e;
	print $out "INSERT INTO known_plugins (name, hash, note) SELECT '$name', '$hash->{hash}', 'From $hash->{libname}' WHERE NOT EXISTS (SELECT 1 FROM known_plugins WHERE name = '$name' AND hash = '$hash->{hash}');\n";
}
print $out "COMMIT;\n";
close $out;

print $output unless $err;

exit $err;
