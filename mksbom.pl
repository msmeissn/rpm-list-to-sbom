#!/usr/bin/perl -w
use strict;
use warnings;
use Getopt::Long;
use JSON;
use POSIX qw/strftime setlocale LC_TIME/;

my $url                = "https://github.com/msmeissn/rpm-list-to-sbom";
my $name               = "unset";
my $packageNameIsNEVRA = 0;

GetOptions(
    "url=s"              => \$url,
    "name=s"             => \$name,
    "packageNameIsNEVRA" => \$packageNameIsNEVRA
) or die("Error in command line arguments\n");

# Ensure $url has a trailing slash
$url =~ s|/*$|/|;

my @output = ();

my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
  localtime();
my $curtime = POSIX::strftime( "%Y-%m-%dT%H:%M:%S",
    $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst );

my %map = (
    "spdxVersion"       => "SPDX-2.2",
    "dataLicense"       => "CC-BY-4.0",
    "SPDXID"            => "SPDXRef-DOCUMENT",
    "name"              => $name,
    "documentNamespace" =>
      "https://ftp.suse.com/pub/projects/security/spdx/",    # FIXME
    "CreationInfo" => {
        "Creators" =>
          [ { "Tool" => "https://github.com/msmeissn/rpm-list-to-sbom", } ],
        "Created" => $curtime,
    },
);

my @describes = ("outputfile");    # FIXME
$map{"documentDescribes"} = \@describes;

my @packages = ();

sub multi_hashes {
    my ($filename) = @_;

    # This function reads a named file, chunk-by-chunk,
    # and simultaneously feeds that data into three Digest functions.
    # This means that:
    # - We don't need to read the whole file into RAM
    # - We only need to read the file once for each kind of digest
    # - We can easily extend this to more digest types if necessary
    my %hashers;

    # Only use available hashers
    if ( eval { require Digest::MD5 } ) {
        $hashers{'MD5'} = Digest::MD5->new;
    }
    if ( eval { require Digest::SHA } ) {
        $hashers{'SHA1'}   = Digest::SHA->new(1);
        $hashers{'SHA256'} = Digest::SHA->new(256);
    }

    scalar(%hashers) or die "Could not find any Digest::* modules";

    open my $fh, '<:raw', $filename or die;

    my $data       = "";
    my $offset     = 0;
    my $CHUNK_SIZE = 1024 * 1024;    # 1MB

    while (1) {
        my $success = read $fh, $data, $CHUNK_SIZE, $offset;
        die $! if not defined $success;
        last   if not $success;

        # A chunk was successfully read, so push it to the hashers
        for my $hasher ( keys %hashers ) {
            $hashers{$hasher}->add($data);
        }

        # read will append to $data each time, so clear the buffer now
        $data = "";

        # and increment $offset by how much we actually read
        $offset += $success;
    }

    my @output;
    for my $hasher ( keys %hashers ) {
        push @output,
          {
            "algorithm"     => $hasher,
            "checksumValue" => $hashers{$hasher}->hexdigest
          };
    }
    return \@output;

}

my $json = JSON->new;

foreach my $rpm ( glob("*.rpm") ) {

    my $packageNameMacro = $packageNameIsNEVRA ? "%{NEVRA}" : "%{NAME}";

    # Get the essential data from RPM
    # FIXME: Can this command line be line-wrapped at all?
    my $qs =
qx(rpm -qp \"$rpm\" --queryformat '\\{"description": "%{DESCRIPTION}", "summary": "%{SUMMARY}", "homepage": "%{URL}", "packageName": "${packageNameMacro}", "packageVersion": "%{VERSION}", "sourceInfo": "%{SOURCERPM}", "packageLicenseDeclared": "%{LICENSE}"\\}');
    $qs =~ s|\n|\\n|g;
    my $rpm_info = $json->relaxed->decode($qs);

    # Add extra information
    $rpm_info->{SPDXID}                  = "SPDXRef-$rpm";
    $rpm_info->{packageFilename}         = "$rpm";
    $rpm_info->{filesAnalyzed}           = "false";
    $rpm_info->{packageLicenseConcluded} = $rpm_info->{packageLicenseDeclared};
    $rpm_info->{packageCopyrightText}    = $rpm_info->{packageLicenseDeclared};
    $rpm_info->{checksum}                = multi_hashes($rpm);
    $rpm_info->{downloadLocation}        = "$url$rpm";

    push @packages, $rpm_info;
}

@{ $map{"packages"} } =
  sort { $a->{packageFilename} <=> $b->{packageFilename} } @packages;

print encode_json( \%map );
