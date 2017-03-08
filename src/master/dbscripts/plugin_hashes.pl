#!/usr/bin/perl
use common::sense;
use utf8;
use Getopt::Long;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::Util qw(run_cmd);
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use List::Util qw(reduce);

my ($verbose, $base_url, @branch, @board, @suffix, @packages);

GetOptions
	verbose => \$verbose,
	'base-url=s' => \$base_url,
	'branch=s' => \@branch,
	'board=s' => \@board,
	'suffix=s' => \@suffix,
	'url=s' => \$base_url,
	'package=s' => \@packages
or die "Bad params\n";

die "No URL given\n" unless $base_url;

sub cartesian(@) {
	return reduce {
		[
			map {
				my $append = $_;
				# Append the new item to each already existing array from the previous step
				map [ @$_, $append ], @$a
			} @$b
		]
	} [[]], @_;
}

die "No packages given" unless @packages;

# Generate all possible combinations of board, branch and suffix. This way we
# guess which URLs might exist (not that all of them do).
my @urls = ((map {
	my ($board, $branch, $suffix) = @$_;
	"$base_url/$board-$branch/$suffix/Packages";
} @{cartesian \@board, \@branch, \@suffix}), (map {
	my ($board, $suffix) = @$_;
	"$base_url/$board/$suffix/Packages";
} @{cartesian \@board, \@suffix}));

die "No URLs produced" unless @urls;

sub dbg(@) {
	print STDERR "DBG: ", @_ if $verbose;
}

my $unpack_cmd = dirname($0) . "/pkg-unpack";
my $tmp_dir = tempdir(CLEANUP => 1);
dbg "Using $unpack_cmd to unpack to $tmp_dir\n";
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

my $uid;

sub process_package($$$$) {
	my ($name, $version, $body, $cv) = @_;
	my $output;
	dbg "Unpacking $name-$version\n";
	$uid ++;
	my $finished = run_cmd [$unpack_cmd, "$tmp_dir/$name/$version/$uid", $name, $version],
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
			$hash =~ s/(.{32}).*/$1/;
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

my $tls_ctx = {
	method => "TLSv1_2",
	verify => 1,
	# Unfortunately, the library doesn't support SNI yet. So we disable peer name verification
	# and do so manually in the callback
	verify_cb => sub {
		my ($tls, $ref, $cn, $depth, $preverify_ok, $x509_store_ctx, $cert) = @_;
		# The levels towadrs the root
		return $preverify_ok if $depth;
		# The actual client certificate is of turris.cz
		return AnyEvent::TLS::certname($cert) =~ /CN=turris.cz/;
	}
};

sub get_pkg($$$) {
	my ($url, $name, $version) = @_;
	dbg "Downloading $name/$version $url\n";
	my $cv = cv_get;
	http_get $url, tls_ctx => {}, sub {
		my ($body, $hdrs) = @_;
		if (defined $body and $hdrs->{Status} == 200) {
			handle_package $name, $version, $body;
		} else {
			warn "Couldn't download $url: $hdrs->{Status} $hdrs->{Reason}\n";
			$err = 1;
		}
		$cv->send;
	};
}

sub handle_index($$) {
	my ($url, $body) = @_;
	my %pkgs = map /^Package:\s*(\S+).*Filename:\s*(\S+)/s, split /\n\n/, $body;
	for my $pkg (@packages) {
		my $filename = $pkgs{$pkg};
		if (defined $filename) {
			my $u = $url;
			$u =~ s/Packages$/$filename/;
			my $v = $filename;
			$v =~ s/.*?_//;
			$v =~ s/_.*?$//;
			get_pkg $u, $pkg, $v;
		}
	}
}

sub get_index(_) {
	my ($url) = @_;
	dbg "Downloading $url\n";
	my $cv = cv_get;
	http_get $url, tls_ctx => "high", sub {
		my ($body, $hdrs) = @_;
		if (defined $body and $hdrs->{Status} == 200) {
			dbg "Downloaded index $url\n";
			handle_index $url, $body;
		} else {
			warn "Failed to download index $url: $hdrs->{Status} $hdrs->{Reason}\n";
		}
		$cv->send;
	};
}

get_index for @urls;


sub handle_list($$) {
	my ($name, $list) = @_;
	open my $input, '<:utf8', \$list or die "Error reading list: $!\n";
	my $have_plugin;
	while (<$input>) {
		chomp;
		my ($pname, $version, $flags, $hash) = split;
		next if $flags =~ /R/; # These are to be removed, so ignore them
		#get_pkg $pname, $version if ($packages{$pname});
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

#get_list $_ for @list_names;

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

if ($err) {
	print "BROKEN!;"; # A trick to kill the SQL and force it to also fail.
} else {
	print $output;
}

exit $err;
