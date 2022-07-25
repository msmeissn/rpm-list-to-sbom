# rpm-list-to-sbom
An RPM List to SPDX SBOM generator

written in perl.

You can run the script in a directory which contains either directly or in subdirectories RPMs.

The script will output JSON SPDX 2.2 to STDOUT.

Example:

	perl ./mksbom.pl > output.spdx.json

Optional options:

	--url=URL	sets SPDX tag "downloadLocation"
	--name=NAME	sets SPDX tag "name"

Tag output will currently be random sorted due to perl hash arrays used,
but I am not sure this is relevant.
