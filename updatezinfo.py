#!/usr/bin/env python
import os
import hashlib
import json
import io
import re

from six.moves.urllib import request
from six.moves.urllib.parse import urljoin

from dateutil.zoneinfo import rebuild

# Default metadata file location
METADATA_FILE = "zonefile_metadata.json"
METADATA_OUT_FILE = "zonefile_updated_metadata.json"
METADATA_JSON_OPTIONS = {
    "sort_keys": True,
    "indent": 4,
    "separators": (",", ":")
}

# Metadata file current version specification
METADATA_VERSION = 1.0
METADATA_KEYS = ("metadata_version",
                 "releases_url",
                 "tzversion",
                 "tzdata_file",
                 "tzdata_file_sha512",
                 "zonegroups")

TZDATA_NAME_FORMAT = "tzdata{version}.tar.gz"


def read_metadata_file(fname):
    """
    Reads a metadata file and converted (as best as possible) to the latest
    version. (Note: Implemented before any version history, so for now this is
    just a wrapper for opening the metadata file.)

    :param fname:
        The path to the location of the valid metadata file.
    """
    with io.open(fname, 'r') as f:
        metadata = json.load(f)

    return metadata


def write_metadata_file(fname, **kwargs):
    """
    Writes a metadata file using the current version conventions. Exceptions
    raised in a call to :func:`read_metadata_file` may be raised if an
    exception was raised when trying to read the default metadata file and
    any required keys are missing.

    Extra arguments not in ``METADATA_KEYS`` will not be filtered out.

    :param fname:
        Full path to the output file.

    """
    kwargs["metadata_version"] = METADATA_VERSION

    # Replace any missing arguments with arguments from the default file
    default_exception = None
    try:
        dflt_kwargs = read_metadata_file(METADATA_FILE)
    except IOError as default_exception:
        # If the default file isn't there but you've specified all the
        # arguments, this isn't really exceptional. Exception will be
        # re-raised in the next step if it's a problem.
        pass

    for key in METADATA_KEYS:
        if key not in kwargs:
            if default_exception is not None:
                raise default_exception

            kwargs.set(dflt_kwargs[key])

    # Write the new metadata file.
    with open(fname, 'w') as f:
        json.dump(kwargs, f, **METADATA_JSON_OPTIONS)


def get_file_hash(fname):
    """ Retrieve the file's SHA512 hash as a hex digest """
    with open(fname, 'rb') as tzfile:
        sha_hasher = hashlib.sha512()
        sha_hasher.update(tzfile.read())

    return sha_hasher.hexdigest()


def valid_hash(fname, hash):
    """
    Checks that the file's hash matches the known value.

    :returns:
        Returns a boolean representing whether or not the hashes match.
    """
    with open(fname, 'rb') as tzfile:
        sha_hasher = hashlib.sha512()
        sha_hasher.update(tzfile.read())
        sha_512_file = sha_hasher.hexdigest()

        return sha_512_file == sha_hasher.hexdigest()


def extract_version(fname):
    ver_re = TZDATA_NAME_FORMAT.replace('.', r'\.') + '$'
    ver_re = ver_re.format(version='(?P<v>[0-9]{4}[a-z])')

    m = re.search(ver_re, fname)
    if m is not None:
        return m.group('v')
    else:
        return None


def main(args):
    # Handle argument logic to see what needs to be done.
    md_fname = METADATA_FILE

    if args.input_file is not None:
        # If an input file has been specified, check if it's a tarball or a
        # JSON file and proceed accordingly.
        if args.input_file.endswith("json"):
            md_fname = args.input_file

        elif args.input_file.endswith("tar.gz"):
            args.tzdata = args.input_file

            # Try to get version info from the filename if necessary
            if args.version is None:
                args.version = extract_version(args.tzdata)

    # Create a valid tzdata file if none was specified and version has been
    # overridden
    if args.version is not None and args.tzdata is None:
        args.tzdata = TZDATA_NAME_FORMAT.format(version=args.version)
    elif args.version is None and args.tzdata is not None:
        args.version = extract_version(args.tzdata) or "unknown_version"

    metadata = read_metadata_file(md_fname)

    # Override any options from the command line
    key_mapping = {"tzversion": args.version,
                   "releases_url": args.releases_url,
                   "tzdata_file_sha512": args.hash,
                   "tzdata_file": args.tzdata}

    for key, value in key_mapping.items():
        if value is not None:
            metadata[key] = value

    # Download the tzdata file if it's not present already
    if not os.path.isfile(metadata['tzdata_file']):
        tzdata_file_url = urljoin(metadata["releases_url"],
                                  metadata["tzdata_file"])

        print("Downloading tz file...")
        request.urlretrieve(tzdata_file_url, metadata['tzdata_file'])

    # Check the hash before we do anything with the file
    tzdata_hash = get_file_hash(metadata["tzdata_file"])
    known_hash = metadata.get("tzdata_file_sha512", None)
    if not args.no_hash:
        if not known_hash:
            raise ValueError("No hash provided, use --no-hash to skip.")

        assert tzdata_hash == known_hash, "Hash check failed"

    metadata['tzdata_file_sha512'] = tzdata_hash

    print("Updating timezone information...")
    rebuild.rebuild(metadata['tzdata_file'], zonegroups=metadata['zonegroups'],
                    metadata=metadata)

    # Store the new metadata file
    write_metadata_file(args.metadata_out or METADATA_OUT_FILE, **metadata)

    print("Done.")


if __name__ == "__main__":
    # Set up the argument parser.
    import argparse
    dflt_from_zoneinfo = ("By default, this is taken from the " +
                          "zoneinfo_metadata file.")

    parser = argparse.ArgumentParser(description="Update the tzinfo file.")

    parser.add_argument("input_file", metavar="IN", type=str, nargs='?',
                        default=None,
                        help="An input file, which can either be an IANA " +
                             "tzdata tarball or a JSON zoneinfo metadata file.")

    parser.add_argument("-d", "--tzdata", type=str, default=None,
                        help="An IANA tzdata file. This will override any " +
                             "URL parameters. If --version is not specified," +
                             " the version will be inferred, if posssible, " +
                             "from the filename. " + dflt_from_zoneinfo)

    parser.add_argument("-o", "--metadata-out", type=str, default=None,
                        help="A location to save the zoneinfo_metadata file" +
                             "default is " + METADATA_OUT_FILE)

    parser.add_argument("-v", "--version", type=str, default=None,
                        help="The version of the timezone data file to " +
                        "retrieve. " + dflt_from_zoneinfo)

    parser.add_argument("-ru", "--releases-url", type=str, default=None,
                        help="The base URL from which the tzdata files are " +
                             "released. " + dflt_from_zoneinfo)

    parser.add_argument("-ha", "--hash", type=str, default=None,
                        help="An sha512 hash of the tzdata file used to " +
                             "validate the file if the --no-hash flag is " +
                             "not specified. " + dflt_from_zoneinfo)

    parser.add_argument("--no-hash", action="store_true",
                        help="If present, the file hash will still be " +
                             "generated, but it will not be validated " +
                             "against the provided hash.")

    args = parser.parse_args()

    main(args)
