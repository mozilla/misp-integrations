#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler
from OTXv2 import OTXv2, IndicatorTypes
from pandas.io.json import json_normalize
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


def main():
    global logger
    environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", help="Print debug messages")
    args = parser.parse_args()

    with open(argv[0].replace(".py", ".yml"), "r") as configyaml:
        config = load(configyaml, Loader=Loader)

    otx_api_key = config.get("otx_api_key", "<OTXAPIKEY>")
    misp_api_key = config.get("misp_api_key", "<MISPAPIKEY>")
    misp_api_url = config.get("misp_api_url", "<APIKEY>")

    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    logger.level = logging.DEBUG
    logger.debug("Started and initialized")

    pulses = []
    # otx = OTXv2(otx_api_key)
    # pulses = otx.getall(modified_since=datetime.today() - timedelta(days=3))
    print(len(pulses))
    random_pulse = {
        "industries": [],
        "tlp": "white",
        "description": "",
        "created": "2019-04-16T15:29:09.061000",
        "tags": ["vietnam"],
        "modified": "2019-04-16T15:29:09.061000",
        "author_name": "AlienVault",
        "public": 1,
        "extract_source": [],
        "references": ["http://blog.macnica.net/blog/2019/04/oceanlotus-218a.html"],
        "targeted_countries": [],
        "indicators": [
            {
                "indicator": "53efaac9244c24fab58216a907783748d48cb32dbdc2f1f6fb672bd49f12be4c",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "FileHash-SHA256",
                "id": 1635912613,
            },
            {
                "indicator": "outlook.updateoffices.net",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "hostname",
                "id": 1635912634,
            },
            {
                "indicator": "https://outlook.updateoffices.net/vale32.png",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "URL",
                "id": 1919125999,
            },
            {
                "indicator": "7fd526e1a190c10c060bac21de17d2c90eb2985633c9ab74020a2b78acd8a4c8",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "FileHash-SHA256",
                "id": 1919126000,
            },
            {
                "indicator": "358df9aba78cf53e38c2a03c213c31ba8735e3936f9ac2c4a05cfb92ec1b2396",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "FileHash-SHA256",
                "id": 1919126001,
            },
            {
                "indicator": "https://outlook.updateoffices.net/vean32.png",
                "description": "",
                "title": "",
                "created": "2019-04-16T15:29:10",
                "content": "",
                "type": "URL",
                "id": 1919126002,
            },
        ],
        "more_indicators": False,
        "revision": 1,
        "adversary": "Ocean Lotus",
        "id": "5cb5f4c52468ec36636c6412",
        "name": "Evasion Techniques used by OceanLotus",
    }
    pulses.append(random_pulse)

    misp = ExpandedPyMISP(misp_api_url, misp_api_key, True)

    for pulse in pulses:
        event = MISPEvent()
        event.distribution = 0
        event.threat_level_id = 1
        event.analysis = 2
        if "name" in pulse:
            event.info = pulse["name"]
        if "author_name" in pulse:
            event.info = pulse["author_name"] + " | " + pulse["name"]

        try:
            dt = date_parser.parse(pulse["created"])
        except (ValueError, OverflowError):
            logger.error("Cannot parse Pulse 'created' date")
            dt = datetime.utcnow()
        event["date"] = dt

        # event_obj = misp.add_event(event)
        # event_id = event_obj.id
        # print("Event id: %s" % event_id)

        # for indicator in pulse["indicators"]:
        #    indicator_kwargs = {"to_ids": True}
        #    indicator_kwargs["comment"] = indicator["description"]
        #    if indicator["type"] == "FileHash-SHA256":
        #        misp.add_hashes(
        #            event_id, sha256=indicator["indicator"], **indicator_kwargs
        #        )
        #    if indicator["type"] == "FileHash-SHA1":
        #        misp.add_hashes(
        #            event_id, sha1=indicator["indicator"], **indicator_kwargs
        #        )
        #    if indicator["type"] == "FileHash-MD5":
        #        misp.add_hashes(
        #            event_id, md5=indicator["indicator"], **indicator_kwargs
        #        )
        #    if "description" in indicator:
        #        indicator_description = indicator["description"]

    # event = misp.get_event(event_id)
    # print(event.to_json())


if __name__ == "__main__":
    main()
