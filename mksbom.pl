#!/usr/bin/perl -w
use strict;
use POSIX qw/strftime setlocale LC_TIME/;
use JSON;
use Getopt::Long;

my $url = "https://github.com/msmeissn/rpm-list-to-sbom";
my $name = "unset";

GetOptions ( "url=s" => \$url, "name=s"   => \$name)
	or die("Error in command line arguments\n");


my @output = ();

my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
my $curtime = POSIX::strftime("%Y-%m-%dT%H:%M:%S",$sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst );

my %map = (
	"spdxVersion"		=> "SPDX-2.2",
	"dataLicense"		=> "CC-BY-4.0",
	"SPDXID"		=> "SPDXRef-DOCUMENT",
	"name"			=> $name,
	"documentNamespace"	=> "https://ftp.suse.com/pub/projects/security/spdx/",	# FIXME
	"CreationInfo" 		=> {
		"Creators"	=> [ {"Tool" => $0, } ],
		"Created"	=> $curtime,
	},
);

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

	my $url = `rpm -qp --qf '%{URL}\n' $rpm`;
	chomp($url);
	my $sourceinfo = `rpm -qp --qf '%{SOURCERPM}\n' $rpm`;
	chomp($sourceinfo);

	my $description = `rpm -qp --qf '%{DESCRIPTION}\n' $rpm`;
	chomp($description);
	my $summary = `rpm -qp --qf '%{SUMMARY}\n' $rpm`;
	chomp($summary);

	#"checksum": { "algorithm": "SHA1", "checksumValue": "14ff98203c3ddd2bd4803c00b5225d2551ca603c" },
	my $sha2 = `sha256sum $rpm`;
	chomp($sha2);
	$sha2 =~ s/ .*//;

	my %package = (
		"description"			=> $description,
		"summary"			=> $summary,
		"homepage"			=> $url,
		"packageName"			=> $name, # FIXME ... full version and arch?
		"packageVersion"		=> $version,
		"sourceInfo"			=> $sourceinfo,
		"packageFilename"		=> $basename,
		"SPDXID" 			=> "SPDXRef-$basename",
		#"downloadLocation"		=> "$url$rpm",	# FIXME
		"filesAnalyzed" 		=> "false",
		"packageLicenseConcluded"	=> $license,
		"packageLicenseDeclared" 	=> $license,
		"packageCopyrightText"		=> $license,
		"checksum"			=> [ {
			"algorithm" 	=> "SHA256",
			"checksumValue"	=> $sha2,
		} ],
	);
	push @packages,\%package;
}

$map{"packages"} = \@packages;

# "externalDocumentRefs": [ ? 
#   "relationships": [ ? 

print encode_json(\%map);
