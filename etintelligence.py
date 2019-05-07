#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler
from datetime import datetime, timedelta
from dateutil import parser as date_parser
import requests
import json
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute


def link_attribute(misp, event_id, attr_type, category, value, comment):
    # an attribute stuffing
    if len(value) < 1:
        value = "UNKNOWN"
    attribute = MISPAttribute()
    attribute.type = attr_type
    attribute.value = value
    attribute.category = category
    attribute.comment = comment

    attribute_to_change = misp.add_attribute(event_id, attribute)


def setup_logging(stream=stderr, level=logging.INFO):
    formatstr = (
        "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    )
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


def main():
    global logger
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    with open(argv[0].replace(".py", ".yml"), "r") as configyaml:
        config = load(configyaml, Loader=Loader)

    etintel_api_key = config.get("etintel_api_key", "<ETINTELAPIKEY>")
    iprep_url = (
        "https://rules.emergingthreatspro.com/"
        + etintel_api_key
        + "/reputation/iprepdata.json"
    )
    domainrep_url = (
        "https://rules.emergingthreatspro.com/"
        + etintel_api_key
        + "/reputation/domainrepdata.json"
    )
    misp_api_key = config.get("misp_api_key", "<MISPAPIKEY>")
    misp_api_url = config.get("misp_api_url", "<APIKEY>")
    expiration = config.get("expiration", "3600")

    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    logger.level = logging.DEBUG
    logger.debug("Started and initialized")

    r = requests.get(iprep_url)
    iprepraw = json.loads(r.text)
    r = requests.get(domainrep_url)
    domainrepraw = json.loads(r.text)

    del (iprepraw["ip"])
    iprep = {}
    for ipaddr in iprepraw:
        for repcat in iprepraw[ipaddr]:
            if repcat in iprep:
                if int(iprepraw[ipaddr][repcat]) > 100:
                    iprep[repcat][ipaddr] = iprepraw[ipaddr][repcat]
            else:
                if int(iprepraw[ipaddr][repcat]) > 100:
                    iprep[repcat] = {}
                    iprep[repcat][ipaddr] = iprepraw[ipaddr][repcat]

    misp = ExpandedPyMISP(misp_api_url, misp_api_key, True)

    ioctype = "ip"
    for cat in iprep:
        event = MISPEvent()
        event.distribution = 0
        event.threat_level_id = 1
        event.analysis = 2

        event.info = "Emerging Threats" + " | " + cat

        event["date"] = datetime.utcnow()

        event_obj = misp.add_event(event)
        event_id = event_obj.id
        print("Event id: %s" % event_id)

        link_attribute(
            misp, event_id, "campaign-name", "Attribution", cat, "Campaign name"
        )
        link_attribute(
            misp, event_id, "text", "Internal reference", "Emerging Threats", "Source"
        )
        link_attribute(
            misp,
            event_id,
            "other",
            "Internal reference",
            expiration,
            "Expiration in seconds",
        )
        link_attribute(
            misp,
            event_id,
            "link",
            "External analysis",
            "http://threatintel.proofpoint.com/",
            "URL",
        )

        for ioc in iprep[cat]:
            indicator_kwargs = {"to_ids": True}
            indicator_kwargs["comment"] = cat
            if ioctype == "ip":
                misp.add_ipdst(event_id, ioc, **indicator_kwargs)


if __name__ == "__main__":
    main()
