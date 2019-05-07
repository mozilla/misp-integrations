#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler
from OTXv2 import OTXv2Cached, IndicatorTypes
from datetime import datetime, timedelta
from dateutil import parser as date_parser
import uuid
import sys
from pymisp import (
    ExpandedPyMISP,
    MISPEvent,
    MISPOrganisation,
    MISPUser,
    Distribution,
    ThreatLevel,
    Analysis,
    MISPObject,
    MISPAttribute,
)


def init_logging(stream=stderr, level=logging.INFO):
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
        cf = load(configyaml, Loader=Loader)

    config["debug"] = cf.get("debug", False)
    config["otx_api_key"] = cf.get("otx_api_key", "<ETINTELAPIKEY>")
    config["misp_api_key"] = cf.get("misp_api_key", "<MISPAPIKEY>")
    config["misp_api_url"] = cf.get("misp_api_url", "<APIKEY>")
    config["expires"] = cf.get("expires", "3600")
    config["skeleton"] = cf.get("event_skeleton", "eventskeleton.json")

    return config


def create_event_obj(ep):
    event = MISPEvent()
    event.load_file(config["skeleton"])
    event.threat_level_id = ThreatLevel.high
    event.analysis = Analysis.completed
    event.distribution = Distribution.your_organisation_only
    event.published = True
    event.uuid = str(uuid.uuid4())
    event.date = ep["dt"]
    event.info = "{0} | {1}".format(ep["author_name"], ep["name"])

    event.add_attribute(
        "campaign-name",
        ep["name"],
        attribute="Attribution",
        comment="Campaign name",
        disable_correlation=True,
    )
    event.add_attribute(
        "text",
        ep["author_name"],
        attribute="Internal reference",
        comment="Source",
        disable_correlation=True,
    )
    event.add_attribute(
        "text",
        ep["description"],
        attribute="External analysis",
        disable_correlation=True,
    )
    for ref in ep["references"]:
        event.add_attribute(
            "link",
            ref,
            attribute="External analysis",
            comment="URL",
            disable_correlation=True,
        )

    return event


def enrich_pulses(pulses):
    eps = []

    for pulse in pulses:
        if "name" in pulse:
            pulse["info"] = pulse["name"]
        if "author_name" in pulse:
            pulse["info"] = pulse["author_name"] + " | " + pulse["name"]

        print(pulse["created"], pulse["name"])
        try:
            dt = date_parser.parse(pulse["created"])
        except (ValueError, OverflowError):
            log.error("Cannot parse Pulse 'created' date")
            dt = datetime.utcnow()
        pulse["dt"] = dt

        if len(pulse["references"]) < 1:
            pulse["references"] = []
            pulse["references"].append("https://misp.infosec.mozilla.org")

        eps.append(pulse)

    return eps


def fetch_pulses(config):
    pulses = []

    otx = OTXv2Cached(config["otx_api_key"])
    otx.update()
    pulses = otx.getall(
        modified_since=datetime.today() - timedelta(minutes=15), limit=0
    )

    return pulses


def map_otx_to_misp(indicator):
    attrmap = {}

    attrmap["value"] = indicator["indicator"]
    attrmap["desc"] = indicator["description"]

    if indicator["type"] == "FileHash-SHA256":
        attrmap["type"] = "sha256"
        return attrmap
    elif indicator["type"] == "FileHash-SHA1":
        attrmap["type"] = "sha1"
        return attrmap
    elif indicator["type"] == "FileHash-MD5":
        attrmap["type"] = "md5"
        return attrmap
    elif indicator["type"] == "URI" or indicator["type"] == "URL":
        attrmap["type"] = "url"
        return attrmap
    elif indicator["type"] == "domain":
        attrmap["type"] = "domain"
        return attrmap
    elif indicator["type"] == "hostname":
        attrmap["type"] = "hostname"
        return attrmap
    elif indicator["type"] == "IPv4" or indicator["type"] == "IPv6":
        attrmap["type"] = "ip-dst"
        return attrmap
    elif indicator["type"] == "email":
        attrmap["type"] = "email-src"
        return attrmap
    elif indicator["type"] == "Mutex":
        attrmap["type"] = "mutex"
        return attrmap
    elif indicator["type"] == "CVE":
        attrmap["type"] = "vulnerability"
        return attrmap
    elif indicator["type"] == "FileHash-IMPHASH":
        attrmap["type"] = "imphash"
        return attrmap
    elif indicator["type"] == "FileHash-PEHASH":
        attrmap["type"] = "pehash"
        return attrmap
    elif indicator["type"] == "FilePath":
        attrmap["type"] = "filename"
        return attrmap
    elif indicator["type"] == "YARA":
        attrmap["type"] = "yara"
        return attrmap
    else:
        log.warning("Unsupported indicator type: %s" % indicator["type"])

    return attrmap


def create_attr_obj(mattr):
    attr = MISPAttribute()

    attr.disable_correlation = False

    # attrmap["desc"]
    attr.category = "Network activity"
    attr.value = mattr["value"]
    attr.type = mattr["type"]
    attr.comment = mattr["desc"]
    attr.to_ids = True
    attr.add_tag("expires:" + config["expires"])
    if attr.type in [
        "ip-dst",
        "ip-src",
        "hostname",
        # "domainname",
        # "url",
        "md5",
        "sha1",
        "sha256",
    ]:
        attr.add_tag("nsm")

    return attr


def main():
    misp = ExpandedPyMISP(
        config["misp_api_url"], config["misp_api_key"], True, cert="test1.pem"
    )

    pulses = fetch_pulses(config)

    if len(pulses) > 0:
        epulses = enrich_pulses(pulses)

        for ep in epulses:
            event = create_event_obj(ep)
            event.add_tag("nsm")

            for indicator in ep["indicators"]:
                mattr = map_otx_to_misp(indicator)
                attr = create_attr_obj(mattr)
                event.attributes.append(attr)
            event_json = event.to_json().replace("\n", "")
            r = misp.add_event(event_json)


if __name__ == "__main__":
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    config = init_config()

    if args.debug or config["debug"]:
        log = init_logging(level=logging.DEBUG)
    else:
        log = init_logging(level=logging.INFO)

    main()
