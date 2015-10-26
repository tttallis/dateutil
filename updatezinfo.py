#!/usr/bin/env python
import os
import hashlib
import json
import io
import re

from six.moves.urllib import request
from six.moves.urllib.parse import urljoin, urlparse

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
ZONEINFO_NAME_RE = "dateutil-zoneinfo(.*?).tar.gz"


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


def assert_valid_hash(fpath, known_hash, no_hash=False):
    """
    Wrapper for file hash check that throws consistent errors.

    :param fname:
        The path to the file to hash

    :param known_hash:
        The known hexdigest of the sha512 hash of the file.

    :raises ValueError:
        Raised if no hash is provided and no_hash is ``False``.

    :raises AssertionError:
        Raised if the hash of the file does not match the known hash.
    """
    if no_hash:
        return

    if not hash:
            raise ValueError("No hash provided, use --no-hash to skip.")

    assert get_file_hash(fname) == hash, "Hash check failed"


def extract_tzdata_version(fname, tzdata=True):
    """
    Extract the version from the standard IANA tzdata naming format.
    """
    ver_re = TZDATA_NAME_FORMAT.replace('.', r'\.') + '$'
    ver_re = ver_re.format(version='(?P<v>[0-9]{4}[a-z])')

    m = re.search(ver_re, fname)
    return m.group('v') if m is not None else None


def update_from_zoneinfo(zinfo_fname, hash, no_hash=False):
    """ Update the timezones from a zoneinfo file """
    # Update the zoneinfo metadata
    pass


def update_from_tzdata(tzdata, version, md_fname, releases_url,
                       hash, no_hash, metadata_out=None):
    """ Update the zoneinfo file from a tzdata file """
    # Create a valid tzdata file if none was specified and version has been
    # overridden
    if version is not None and tzdata is None:
        tzdata = TZDATA_NAME_FORMAT.format(version=version)
    elif version is None and tzdata is not None:
        version = extract_tzdata_version(tzdata) or "unknown_version"

    metadata = read_metadata_file(args.md_fname)

    # Override any options from the command line
    key_mapping = {"tzversion": version,
                   "releases_url": releases_url,
                   "tzdata_file_sha512": hash,
                   "tzdata_file": tzdata}

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
    if not no_hash:
        if not known_hash:

        assert tzdata_hash == known_hash, "Hash check failed"

    metadata['tzdata_file_sha512'] = tzdata_hash

    print("Updating timezone information...")
    rebuild.rebuild(metadata['tzdata_file'], zonegroups=metadata['zonegroups'],
                    metadata=metadata)

    # Store the new metadata file
    write_metadata_file(metadata_out or METADATA_OUT_FILE, **metadata)

    print("Done.")


def download_file(url, local_path, verbose=False):
    if verbose:
        urlparsed = urlparse(url)
        xx, fname = os.path.split(urlparsed.path)
        print("Downloading {fname} to {local}...".format(fname=fname,
                                                         local=local_path))
    request.urlretrieve(url, local_path)


def main(input_file=None, version=None, zoneinfo=None, tzdata=None,
         releases_url=None, hash=None, no_hash=False,
         file_output=None, metadata_out=None, verbose=False):
    # Handle argument logic to see what needs to be done.
    md_fname = METADATA_FILE

    if input_file is not None:
        # If an input file has been specified, check if it's a tarball or a
        # JSON file and proceed accordingly.
        if input_file.endswith("json"):
            md_fname = input_file

        elif input_file.endswith("tar.gz"):
            tzdata = input_file

            # Try to get version info from the filename if necessary
            if version is None:
                version = extract_tzdata_version(tzdata)

            # In this case, check to see if the name matches a zoneinfo file
            if version is None:
                if re.match(ZONEINFO_NAME_RE, input_file):
                    zoneinfo = input_file

    fpath = zoneinfo or tzdata
    if fpath is not None:
        if urlparse(fpath).netloc:
            # This is a URL, download it in the current directory
            tmp, fname = os.path.split(fpath)
            download_file(fpath, fname)
            fpath = fname

        # Hash whatever file we have
        assert_valid_hash(fpath, hash, no_hash)

    if zoneinfo:
        update_from_zoneinfo(zoneinfo,
                             hash=hash,
                             no_hash=no_hash)
    else:
        update_from_tzdata(tzdata,
                           version=version,
                           md_fname=md_fname,
                           releases_url=releases_url,
                           hash=hash,
                           no_hash=no_hash,
                           metadata_out=metadata_out)


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

    parser.add_argument("-z", "--zoneinfo", type=str, default=None,
                        help="A dateutil zoneinfo file. All other parameters" +
                             " will be effectively ignored. This zoneinfo " +
                             "file will have its metadata updated to " +
                             "the latest version and it will be applied " +
                             "directly.")

    parser.add_argument("-d", "--tzdata", type=str, default=None,
                        help="An IANA tzdata file. This will override any " +
                             "URL parameters. If --version is not specified," +
                             " the version will be inferred, if posssible, " +
                             "from the filename. " + dflt_from_zoneinfo)

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

    parser.add_argument("-fo", "--file-output", type=str, default=None,
                        help="Output the zoneinfo file to this path. By " +
                             "default the file is installed for use by " +
                             "dateutil.")

    parser.add_argument("-mo", "--metadata-out", type=str, default=None,
                        help="A location to save the zoneinfo_metadata file" +
                             "default is " + METADATA_OUT_FILE)

    parser.add_argument("-q", "--quiet", action="store_false",
                        help="Suppress status messages.")

    args = parser.parse_args()

    # The "quiet" flag is really a "verbose" flag defaulting to 'off', so it
    # should be renamed before being passed to the main function (which has the
    # opposite default).
    kwargs = vars(args)
    kwargs['verbose'] = kwargs['quiet']
    del kwargs['quiet']

    main(**kwargs)
