#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename, path, close
from tempfile import mkstemp
from logging.handlers import SysLogHandler
import sys
import yaml
import json
import requests
from requests.packages.urllib3.util import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import HTTPError
from netaddr import IPAddress as isipaddress
from netaddr.core import AddrFormatError
from validators import domain as isdomain


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
    config["etintel_api_key"] = cf.get("etintel_api_key", "<ETINTELAPIKEY>")
    config["expires"] = cf.get("expires", "3600")
    config["inteldir"] = cf.get("inteldir")
    config["intelfile"] = cf.get("intelfile")
    config["wlfile"] = cf.get("wlfile", "whitelist.yml")
    config["proxy"] = cf.get("proxy", None)
    config["ip"] = "https://rules.emergingthreatspro.com/" + config["etintel_api_key"] + "/reputation/iprepdata.json"
    config["domain"] = (
        "https://rules.emergingthreatspro.com/" + config["etintel_api_key"] + "/reputation/domainrepdata.json"
    )
    config["reptypes"] = cf.get("reptypes", ["ip", "domain"])
    config["thresholds"] = cf.get("thresholds")
    config["nsmcats"] = cf.get("nsmcats")

    with open(config["wlfile"], "r") as wl:
        wlmap = wl.read()
        config["whitelist"] = yaml.load(wlmap)
        del wlmap

    return config


def whitelisted(ioc):
    if ioc in config["whitelist"]:
        return True


def fetch_replists(reptypes):
    ret = Retry(total=5, status_forcelist=[429, 500, 502, 503], backoff_factor=5)
    a = HTTPAdapter(pool_connections=10, max_retries=ret)
    with requests.Session() as s:
        s.mount("https://", a)
        if config["proxy"]:
            s.proxies = {"https": config["proxy"]}
        replists = {}
        for rt in reptypes:
            try:
                r = s.get(config[rt])
                r.raise_for_status()
                replists[rt] = r.json()
            except HTTPError as e:
                log.error(f"HTTPS request failed to download the {rt} reputation list: {e}")
            except Exception as e:
                log.error(f"Something went south and I failed to download the {rt} reputation list: {e}")

    return replists


def map_et_to_zeek(replist, reptype, config, state):
    for ioc in replist.keys():
        fields = []

        if whitelisted(ioc):
            continue
        else:
            if reptype == 'ip':
                try:
                    isipaddress(ioc)
                except AddrFormatError as e:
                    continue
                ioctype = 'Intel::ADDR'
            if reptype == 'domain':
                if not isdomain(ioc):
                    continue
                ioctype = 'Intel::DOMAIN'
            for k, v in replist[ioc].items():
                iiv = int(v)
                c = "Low"
                if iiv > config["thresholds"]["medium"]:
                    c = "Medium"
                if iiv > config["thresholds"]["high"]:
                    c = "High"
                if k not in config['nsmcats']:
                    # print("dee-lete 1 {}".format(ioc))
                    continue
                if c not in config['nsmcats'][k]:
                    # print("dee-lete 2 {}".format(ioc))
                    continue
                fields = [
                    ioc,
                    ioctype,
                    "ET",
                    "{}:{}".format(k, c),
                    "https://threatintel.proofpoint.com",
                    "useless",
                    "F",
                    "3600",
                ]
                line = "\t".join(fields).encode("utf-8")
                state.append(line)

    return state


def write_state(state, config):
    header = (
        "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.uuid\tmeta.do_notice\tmeta.expire\n"
    )

    fd, tmppath = mkstemp(suffix='.tmp', prefix='et.intel.', dir=config["inteldir"])

    with open(tmppath, 'wb') as tmp:
        tmp.write(header.encode("utf-8"))

        for line in state:
            tmp.write(line)
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
    if (ratio > 0.5) and (ratio < 1.5):
        rename(newpath, oldpath)
    else:
        log.error("Huge feed size difference, preserving old data")


def main():
    state = []

    replists = fetch_replists(config["reptypes"])

    for replist in config["reptypes"]:
        state = map_et_to_zeek(replists[replist], replist, config, state)

    write_state(state, config)


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
