#!/usr/bin/env python3
import argparse
import logging
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


def kill_tabs(string):
    return string.replace("\t", " ")


def main():
    global logger
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    with open(argv[0].replace(".py", ".yml"), "r") as configyaml:
        config = load(configyaml, Loader=Loader)

    misp_api_key = config.get("misp_api_key", "<MISPAPIKEY>")
    misp_api_url = config.get("misp_api_url", "<APIKEY>")
    intelfile = config.get("intelfile", "misp.intel")
    minsize = config.get("minsize", 8192)

    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    logger.level = logging.DEBUG
    logger.debug("Started and initialized")

    misp = ExpandedPyMISP(misp_api_url, misp_api_key, True, cert="test1.pem")

    # XXX: add date_from
    header = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.uuid\tmeta.do_notice\tmeta.expire\n"
    # events = misp.search(controller="events", publish_timestamp="30d", tags="nsm")
    datefrom = (datetime.today() - timedelta(days=30)).strftime("%Y-%m-%d")
    events = misp.search(
        controller="events",
        published=True,
        tags="nsm",
        threatlevel=[3, 4],
        date_from=datefrom,
    )
    tmpfile = intelfile + ".tmp"
    with open(tmpfile, "wb") as f:
        f.write(header.encode("utf-8"))
        for event in events:
            iocline = {}
            fields = []
            inteltype = "UNKNOWN"
            desc = "UNKNOWN"
            expire = "3600"
            source = None
            url = None
            notice = "F"

            for attr in event["Event"]["Attribute"]:
                if attr["type"] == "md5":
                    inteltype = "Intel::FILE_HASH"
                if attr["type"] == "sha1":
                    inteltype = "Intel::FILE_HASH"
                if attr["type"] == "sha256":
                    inteltype = "Intel::FILE_HASH"
                if attr["type"] == "url":
                    inteltype = "Intel::URL"
                if attr["type"] == "hostname":
                    inteltype = "Intel::DOMAIN"
                # XXX: it does not work
                if attr["type"] == "domain":
                    inteltype = "Intel::DOMAIN"
                if attr["type"] == "ipv4":
                    inteltype = "Intel::ADDR"
                if attr["type"] == "ipv6":
                    inteltype = "Intel::ADDR"
                    # XXX: boo, need to strip the http://
                if attr["comment"] == "Source":
                    source = kill_tabs(attr["value"])
                if attr["category"] == "Attribution":
                    desc = kill_tabs(attr["value"])
                if attr["comment"] == "URL":
                    url = kill_tabs(attr["value"])
                if attr["comment"] == "Notice":
                    notice = "Y"
                if attr["category"] == "Artifacts dropped":
                    iocline["value"] = attr["value"]
                if attr["category"] == "Network activity":
                    iocline["value"] = attr["value"]
                if expire is not None:
                    iocline["expire"] = expire
                if source is not None:
                    iocline["source"] = kill_tabs(source)
                else:
                    iocline["source"] = desc
                if url is not None:
                    iocline["url"] = url
                if len(iocline.keys()) == 4:
                    if "value" not in iocline:
                        continue
                    fields = [
                        iocline["value"],
                        inteltype,
                        iocline["source"],
                        desc,
                        iocline["url"],
                        event["Event"]["uuid"],
                        notice,
                        iocline["expire"],
                    ]
                    try:
                        f.write("\t".join(fields).encode("utf-8"))
                    except IOError as e:
                        logger.exception(
                            "Error when writing to the temporary file {0}".format(e)
                        )
                        exit(3)
                    f.write("\n".encode("utf-8"))
        logger.debug("Data written into a temporary file, flushing buffers")
        # Flush glibc buffers and write dirty pages
        # Does not cause a global pagecache writeback
        f.flush()
        fsync(f.fileno())

    size = stat(tmpfile).st_size
    logger.debug("Size of the new data file {0} bytes".format(size))
    if size > minsize:
        # This is atomic on POSIX
        logger.debug("Atomic rename...")
        try:
            rename(tmpfile, intelfile)
        except OSError as e:
            logger.exception(
                "Failed to move the temporary file to the destination file {0}".format(
                    e
                )
            )
            exit(4)
        logger.debug("Success")
    else:
        logger.error(
            "Truncated data received - received {0} bytes, expected {1} bytes, failing".format(
                size, minsize
            )
        )


if __name__ == "__main__":
    main()
