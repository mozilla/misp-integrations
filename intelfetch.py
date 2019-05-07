#!/usr/bin/env python3
import argparse
import logging
import requests
import json
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler
from datetime import datetime, timedelta
from dateutil import parser as date_parser
from pymisp import ExpandedPyMISP, MISPEvent


def setup_logging(stream=stderr, level=logging.INFO):
    formatstr = (
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


def init_config():
    config = {}
    with open(argv[0].replace(".py", ".yml"), "r") as configyaml:
        config = load(configyaml, Loader=Loader)

    config["intelurl"] = config.get("intelurl", "<Intel URL>")
    config["cat"] = config.get("intelcats", ["cat1", "cat2"])
    config["minsize"] = config.get("minsize", 8192)
    config["etagsfile"] = config.get("etagsfile", "/<SOMEWHERE>/etag.cache")
    config["cert"] = config.get("cert", "<CERTFILE>")
    config["zeekdir"] = config.get("zeekdir", "<PATHTOZEEKINTEL>")

    return config


def intel_save(config, cat, inteldata):
    intelfile = cat + ".intel"
    tmpfile = cat + ".intel.tmp"

    with open(tmpfile, "wb") as f:
        try:
            f.write(inteldata)
        except IOError as e:
            logger.exception("Error when writing to the temporary file {0}".format(e))
            exit(3)
        log.debug("Data written into a temporary file, flushing buffers")
        # Flush glibc buffers and write dirty pages
        # Does not cause a global pagecache writeback
        f.flush()
        fsync(f.fileno())

    size = stat(tmpfile).st_size
    log.debug("Size of the new data file {0} bytes".format(size))
    if size > config["minsize"]:
        # This is atomic on POSIX
        logger.debug("Atomic rename...")
        try:
            rename(tmpfile, intelfile)
        except OSError as e:
            log.exception(
                "Failed to move the temporary file to the destination file {0}".format(
                    e
                )
            )
            exit(4)
        log.debug("Success")
    else:
        log.error(
            "Truncated data received - received {0} bytes, expected {1} bytes, failing".format(
                size, config["minsize"]
            )
        )


def update_etags(config, etags):

    with open(config["etagsfile"], "wb") as c:
        c.write(json.dumps(etags).encode("UTF-8"))


def intel_fetch(config, etags):
    s = requests.Session()

    for c in config["cat"]:

        print(etags[c])
        r = s.get(
            config["intelurl"] + c + ".intel",
            headers={"If-None-Match": etags[c]},
            cert=config["cert"],
        )

        etags[c] = r.headers["ETag"]
        if r.status_code == 304 and len(r.content) == 0:
            print("boo-boo")
        elif r.status_code != 304 and len(r.content) != 0:
            intel_save(config, c, r.content)
        elif r.status_code == 304 and len(r.content) != 0:
            print("an impossible thing just happened")

    update_etags(config, etags)


def get_etags(config):
    etags = {}

    try:
        with open(config["etagsfile"], "rb") as c:
            etags = json.loads(c.read())
    except FileNotFoundError:
        log.debug("Could not open {0} - reseting ETag".format(config["etagsfile"]))

    for c in config["cat"]:
        if c not in etags:
            etags[c] = ""

    return etags


def main():
    etags = get_etags(config)

    inteldata = intel_fetch(config, etags)


if __name__ == "__main__":
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    config = init_config()

    if args.debug:
        log = setup_logging(level=logging.DEBUG)
    else:
        log = setup_logging(level=logging.INFO)
    log.level = logging.DEBUG
    log.debug("Started and initialized")

    main()
