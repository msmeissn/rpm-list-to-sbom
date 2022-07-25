#!/usr/bin/perl -w
use strict;
use POSIX qw/strftime setlocale LC_TIME/;
use JSON;
use Getopt::Long;

my $url = "";
my $name = "unset";

GetOptions ( "url=s" => \$url, "name=s"   => \$name)
	or die("Error in command line arguments\n");


my @output = ();

my %map = (
);

$map{"spdxVersion"} = "SPDX-2.2";
$map{"dataLicense"} = "CC-BY-4.0";
$map{"SPDXID"} = "SPDXRef-DOCUMENT";
$map{"name"} = $name;

my %creationinfo = ();
# foreach creator...
	my @creators = ();
		my %creator = ();
		$creator{"Tool"} = $0;
		push @creators,\%creator;
$creationinfo{"Creators"} = \@creators;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
my $curtime = POSIX::strftime("%Y-%m-%dT%H:%M:%S",$sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst );
$creationinfo{"Created"} = $curtime;

$map{"CreationInfo"} = \%creationinfo;

$map{"documentNamespace"} = "https://ftp.suse.com/pub/projects/security/spdx/";	# FIXME

my @describes = ("outputfile");				# FIXME

$map{"documentDescribes"} = \@describes;

my @packages = ();

my @rpms = `find . -name "*.rpm"`;
foreach my $rpm (@rpms) {
	chomp $rpm;

	my $basename = $rpm;
	$basename =~ s/.*\///;
	my $rpmname = $basename;
	$rpmname =~ s/(.*)-([^-]*-[^-]*)$/$1/;
	my $name = $1;
	my $version = $2;

	my $license = `rpm -qp --qf '%{LICENSE}\n' $rpm`;
	chomp($license);

	my %package = ();
	$package{"packageName"} = $name;		# FIXME ... full version and arch?
	$package{"packageVersion"} = $version;
	$package{"packageFilename"} = $basename;
	$package{"SPDXID"} = "SPDXRef-$name";		# FIXME ... full version and arch?
	#$package{"downloadLocation"} = "$url$rpm";
	$package{"filesAnalyzed"} = "false";

	$package{"packageLicenseConcluded"}	= $license;
	$package{"packageLicenseDeclared"} 	= $license;
	$package{"packageCopyrightText"}	= $license;
	my $url = `rpm -qp --qf '%{URL}\n' $rpm`;
	chomp($url);
	if ($url ne "(none)") {
		$package{"homepage"}			= $url;
	}
	my $sourceinfo = `rpm -qp --qf '%{SOURCERPM}\n' $rpm`;
	chomp($sourceinfo);
	$package{"sourceInfo"}			= $sourceinfo;

	my $description = `rpm -qp --qf '%{DESCRIPTION}\n' $rpm`;
	chomp($description);
	$package{"description"}			= $description;
	my $summary = `rpm -qp --qf '%{SUMMARY}\n' $rpm`;
	chomp($summary);
	$package{"summary"}			= $summary;

		#"checksum": { "algorithm": "SHA1", "checksumValue": "14ff98203c3ddd2bd4803c00b5225d2551ca603c" },
		my @checksums = ();
		my %checksum = ();
		my $sha2 = `sha256sum $rpm`;
		chomp($sha2);
		$sha2 =~ s/ .*//;
		$checksum{'algorithm'}		= "SHA256";
		$checksum{'checksumValue'}	= $sha2;

		@checksums = ( \%checksum );

	$package{'checksum'}=\@checksums;

	push @packages,\%package;
}

$map{"packages"} = \@packages;

# "externalDocumentRefs": [ ? 
#   "relationships": [ ? 

print encode_json(\%map);
