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


def init_logging(stream=stderr, level=logging.INFO):
    formatstr = (
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


def init_config(cfpath):
    config = {}

    if not cfpath:
        cfpath = argv[0].replace(".py", ".yml")
    with open(cfpath, "r") as configyaml:
        cf = load(configyaml, Loader=Loader)

    config["debug"] = cf.get("debug", False)
    config["misp_api_key"] = cf.get("misp_api_key", "<MISPAPIKEY>")
    config["misp_api_url"] = cf.get("misp_api_url", "<APIKEY>")
    config["intelfile"] = cf.get("intelfile", "misp.intel")
    config["minsize"] = cf.get("minsize", 8192)
    config["certfile"] = cf.get("certfile", "cert.pem")
    config["days"] = cf.get("days", 30)
    config["threatlevel"] = cf.get("threatlevel", [3, 4])
    config["tags"] = cf.get("tags", ["tag1", "tag2"])

    return config


def kill_tabs(string):
    return string.replace("\t", " ")


def fixup_url(url):
    return kill_tabs(url.replace("http://", ""))


def stuff_desc(tags):
    for tag in tags:
        if ":" in tag["name"]:
            return tag["name"]


def dropornot(attr):
    for tag in attr["Tag"]:
        if tag["name"] == "nsm":
            return False
    return True


def main():
    misp = ExpandedPyMISP(
        config["misp_api_url"], config["misp_api_key"], True, cert=config["certfile"]
    )

    # XXX: add date_from
    header = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.uuid\tmeta.do_notice\tmeta.expire\n"
    datefrom = (datetime.today() - timedelta(days=config["days"])).strftime("%Y-%m-%d")
    events = misp.search(
        controller="events",
        published=True,
        tags=config["tags"],
        threatlevel=config["threatlevel"],
        date_from=datefrom,
    )
    tmpfile = config["intelfile"] + ".tmp"
    with open(tmpfile, "wb") as f:
        f.write(header.encode("utf-8"))
        for event in events:
            iocline = {}
            fields = []
            inteltype = "UNKNOWN"
            expire = "3600"
            source = None
            url = None
            notice = "F"
            attribution = None
            for attr in event["Event"]["Attribute"]:
                if attr["type"] == "md5":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::FILE_HASH"
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "sha1":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::FILE_HASH"
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "sha256":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::FILE_HASH"
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "url":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::URL"
                    attr["value"] = fixup_url(attr["value"])
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "hostname":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::DOMAIN"
                    localtags = stuff_desc(attr["Tag"])
                # XXX: needs a Zeek code to match subdomains
                if attr["type"] == "domain":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::DOMAIN"
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "ip-dst":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::ADDR"
                    localtags = stuff_desc(attr["Tag"])
                if attr["type"] == "ip-src":
                    if dropornot(attr):
                        continue
                    inteltype = "Intel::ADDR"
                    localtags = stuff_desc(attr["Tag"])
                if attr["comment"] == "Source":
                    source = kill_tabs(attr["value"])
                if attr["category"] == "Attribution":
                    attribution = kill_tabs(attr["value"])
                if attr["comment"] == "URL":
                    url = attr["value"]
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
                    if attribution:
                        desc = attribution
                    else:
                        desc = localtags
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
                        log.exception(
                            "Error when writing to the temporary file {0}".format(e)
                        )
                        exit(3)
                    f.write("\n".encode("utf-8"))
        log.debug("Data written into a temporary file, flushing buffers")
        # Flush glibc buffers and write dirty pages
        # Does not cause a global pagecache writeback
        f.flush()
        fsync(f.fileno())

    size = stat(tmpfile).st_size
    log.debug("Size of the new data file {0} bytes".format(size))
    if size > config["minsize"]:
        # This is atomic on POSIX
        log.debug("Atomic rename...")
        try:
            rename(tmpfile, config["intelfile"])
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


if __name__ == "__main__":
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    cfpath = ""
    if args.config:
        config = init_config(cfpath=args.config)
    else:
        config = init_config(cfpath)

    if args.debug or config["debug"]:
        log = init_logging(level=logging.DEBUG)
    else:
        log = init_logging(level=logging.INFO)

    main()
