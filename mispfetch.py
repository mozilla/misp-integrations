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
import yaml


def init_logging(stream=stderr, level=logging.INFO):
    formatstr = (
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    logger.logThreads = 0
    logger.logProcesses = 0
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
    config["minsize"] = cf.get("minsize", 1024)
    config["certfile"] = cf.get("certfile", "cert.pem")
    config["days"] = cf.get("days", 30)
    config["threatlevel"] = cf.get("threatlevel", [3, 4])
    config["tags"] = cf.get("tags", ["tag1", "tag2"])
    config["mapfile"] = cf.get("mapfile", "misptozeek.yml")
    config["proxies"] = cf.get("proxies", "")

    with open(config["mapfile"], "r") as m:
        map = m.read()
        config["yap"] = yaml.load(map)
        del (map)

    return config


def kill_tabs(string):
    return string.replace("\t", " ")


def fixup_url(url):
    return kill_tabs(url.replace("http://", ""))


def parse_attr_tags(tags):
    ltags = {}
    for tag in tags:
        if tag["name"] == "nsm":
            ltags["nsm"] = True
        if ":" in tag["name"]:
            k, v = tag["name"].split(":")
            if k == "notice":
                ltags["notice"] = v
            elif k == "expires":
                ltags["expires"] = v
            else:
                ltags["desc"] = tag["name"]

    return ltags


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
    st = list(config["yap"].keys())
    tmpfile = config["intelfile"] + ".tmp"
    with open(tmpfile, "wb") as f:
        f.write(header.encode("utf-8"))
        for event in events:
            zf = []
            iocline = {}
            fields = []
            expires = "3600"
            source = None
            link = None
            notice = "F"
            attribution = None
            for attr in event["Event"]["Attribute"]:
                if (
                    attr["category"] == "Artifacts dropped"
                    or attr["category"] == "Network activity"
                ):
                    if attr["type"] not in st:
                        log.error(
                            "Unsupported Zeek type for attribute {0} MISP type {1}".format(
                                attr["value"], attr["type"]
                            )
                        )
                        continue
                    iocline = {}
                    iocline[attr["value"]] = {}
                    iocline[attr["value"]]["type"] = config["yap"][attr["type"]]
                    localtags = {}
                    localtags = parse_attr_tags(attr["Tag"])
                    if "nsm" not in localtags:
                        continue
                    if "notice" in localtags:
                        iocline[attr["value"]]["notice"] = localtags["notice"]
                    if "expires" in localtags:
                        iocline[attr["value"]]["expires"] = localtags["expires"]
                    if "desc" in localtags:
                        iocline[attr["value"]]["desc"] = localtags["desc"]
                    zf.append(iocline)
                elif attr["category"] == "Other":
                    if attr["type"] == "text":
                        if attr["comment"] == "Source":
                            source = kill_tabs(attr["value"])
                        if attr["comment"] == "Notice":
                            notice = "Y"
                elif attr["category"] == "Attribution":
                    if attr["type"] == "campaign-name":
                        attribution = attr["value"]
                elif attr["category"] == "External analysis":
                    if attr["type"] == "link":
                        link = attr["value"]
            if not link:
                link = "https://misp.infosec.mozilla.org"
            if attribution:
                desc = attribution
            for zl in zf:
                e = list(zl.keys())[0]
                if "notice" is None:
                    notice = zl[e]["notice"]
                if "expires" in zl[e]:
                    expires = zl[e]["expires"]
                if "desc" in zl[e]:
                    desc = zl[e]["desc"]
                fields = [
                    e,
                    zl[e]["type"],
                    kill_tabs(source),
                    kill_tabs(desc),
                    link,
                    event["Event"]["uuid"],
                    notice,
                    expires,
                ]
                # print(fields)
                # if "value" not in iocline:
                #   continue
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
