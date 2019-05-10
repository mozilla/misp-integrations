#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename
from logging.handlers import SysLogHandler
from datetime import datetime, timedelta
from pymisp import PyMISP, ExpandedPyMISP, MISPEvent


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

    misp_api_key = config.get("misp_api_key", "<MISPAPIKEY>")
    misp_api_url = config.get("misp_api_url", "<APIKEY>")

    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    logger.level = logging.DEBUG
    logger.debug("Started and initialized")

    misp = PyMISP(misp_api_url, misp_api_key, True, cert="test1.pem")

    ts = datetime.today() - timedelta(days=1)
    events = misp.search(controller="events", timestamp=["96h", "1m"], tags=["ET"])

    for e in events["response"]:
        misp.delete_event(e["Event"]["id"])


if __name__ == "__main__":
    main()
