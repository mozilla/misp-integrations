#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename, path, close
from tempfile import mkstemp
from logging.handlers import SysLogHandler
from OTXv2 import OTXv2Cached, IndicatorTypes
from datetime import datetime, timedelta
from dateutil import parser as date_parser
import uuid
import sys
import yaml


def init_logging(stream=stderr, level=logging.INFO):
    formatstr = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
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
    config["otx_api_key"] = cf.get("otx_api_key", "<ETINTELAPIKEY>")
    config["expires"] = cf.get("expires", "3600")
    config["mapfile"] = cf.get("mapfile")
    config["intelfile"] = cf.get("intelfile")
    config["cache"] = cf.get("cache", "")
    config["proxies"] = cf.get("proxies", "")
    config["wlfile"] = cf.get("wlfile", "whitelist.yml")
    config["proxy"] = cf.get("proxy", None)
    config["inteldir"] = cf.get("inteldir")

    with open(config["mapfile"], "r") as m:
        umap = m.read()
        config["yap"] = yaml.load(umap)
        del umap

    with open(config["wlfile"], "r") as wl:
        wlmap = wl.read()
        config["whitelist"] = yaml.load(wlmap)
        del wlmap

    return config


def kill_tabs(string):
    return string.replace("\t", " ")


def fixup_url(url):
    return kill_tabs(url.replace("http://", ""))


def whitelisted(ioc):
    if ioc in config["whitelist"]:
        return True


def fetch_pulses(config):
    pulses = []

    otx = OTXv2Cached(proxy_https=config["proxy"], api_key=config["otx_api_key"], cache_dir=config["cache"])
    otx.update()
    pulses = otx.getall(modified_since=datetime.today() - timedelta(days=30), limit=0)

    return pulses


def map_ioc_to_line(ioc, meta):
    yap = config["yap"]
    fields = []
    zt = yap["ioctypes"].get(ioc["type"], None)
    if zt == "Intel::URL":
        ioc["indicator"] = fixup_url(ioc["indicator"])
    if zt == None:
        log.warning("Unsupported indicator type: %s" % ioc["type"])
        return []
    fields = [
        ioc["indicator"],
        yap["ioctypes"][ioc["type"]],
        meta["source"],
        meta["desc"],
        meta["url"],
        meta["uuid"],
        meta["do_notice"],
        meta["expire"],
    ]
    line = "\t".join(fields).encode("utf-8")

    return line


def map_pulse_to_zeek(pulse):
    state = []
    meta = {}
    meta["source"] = kill_tabs(pulse["author_name"])
    meta["desc"] = kill_tabs(pulse["name"])
    meta["uuid"] = "useless"
    meta["do_notice"] = "F"
    meta["expire"] = "3600"
    if len(pulse["references"]) < 1:
        pulse["references"] = []
        pulse["references"].append("otx.alienvault.com")
    meta["url"] = ','.join(pulse["references"])
    for ioc in pulse["indicators"]:
        if whitelisted(ioc["indicator"]):
            continue
        else:
            state.append(map_ioc_to_line(ioc, meta))

    return state


def map_otx_to_zeek(pulses, config):
    state = []
    header = (
        "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.uuid\tmeta.do_notice\tmeta.expire\n"
    )
    for p in pulses:
        state.append(map_pulse_to_zeek(p))

    fd, tmppath = mkstemp(suffix='.tmp', prefix='otx.intel.', dir=config["inteldir"])
    with open(tmppath, 'wb') as tmp:
        tmp.write(header.encode("utf-8"))
        for binpulse in state:
            for binioc in binpulse:
                if len(binioc) > 0:
                    tmp.write(binioc)
                    tmp.write("\n".encode("utf-8"))
        tmp.flush()
        fsync(tmp.fileno())
    tmp.close()
    close(fd)
    oldpath = path.join(config["inteldir"], config["intelfile"])
    newpath = tmp.name
    oldsize = 0
    newsize = 0
    try:
        oldsize = path.getsize(oldpath)
    except OSError as e:
        log.error("Failed to verify the size of the new intel file: {}".format(e))
        rename(newpath, oldpath)
        return
    try:
        newsize = path.getsize(tmp.name)
    except OSError as e:
        log.error("Failed to verify the size of the old intel file: {}".format(e))
    ratio = oldsize / newsize
    if (ratio > 0.7) and (ratio < 1.3):
        rename(newpath, oldpath)
    else:
        log.error("Huge feed size difference, preserving old data")


def main():

    pulses = fetch_pulses(config)

    if len(pulses) > 0:
        map_otx_to_zeek(pulses, config)
    else:
        log.error("Failed to fetch pulses")


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
