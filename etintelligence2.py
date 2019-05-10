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
import uuid
import os, sys
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


def init_config(cfpath):
    config = {}

    if not cfpath:
        cfpath = argv[0].replace(".py", ".yml")
    with open(cfpath, "r") as configyaml:
        cf = load(configyaml, Loader=Loader)

    config["debug"] = cf.get("debug", False)
    config["etintel_api_key"] = cf.get("etintel_api_key", "<ETINTELAPIKEY>")
    config["iprep_url"] = (
        "https://rules.emergingthreatspro.com/"
        + config["etintel_api_key"]
        + "/reputation/iprepdata.json"
    )
    config["domainrep_url"] = (
        "https://rules.emergingthreatspro.com/"
        + config["etintel_api_key"]
        + "/reputation/domainrepdata.json"
    )
    config["misp_api_key"] = cf.get("misp_api_key", "<MISPAPIKEY>")
    config["misp_api_url"] = cf.get("misp_api_url", "<APIKEY>")
    config["expires"] = cf.get("expires", "3600")
    config["skeleton"] = cf.get("event_skeleton", "eventskeleton.json")
    config["reptypes"] = cf.get("reptypes", ["ip", "domain"])
    config["nsmcats"] = cf.get("nsmcats", "")
    config["cache"] = cf.get("cache", "/var/www/MISP/.cache")
    config["certfile"] = cf.get("certfile", "cert.pem")

    return config


def inverse_dict(rev):
    if "ip" in rev:
        del (rev["ip"])
    if "domain" in rev:
        del (rev["domain"])
    cats = set([x[0] for x in [list(i) for i in [rev[z].keys() for z in rev]]])
    fwd = {}
    for c in cats:
        for e in rev:
            if c in rev[e].keys():
                w = list(rev[e].values())[0]
                k = c + ":" + w
                if k not in fwd.keys():
                    fwd[k] = []
                fwd[k].append(e)
    return fwd


def fetch_replist(reptype):
    if reptype == "ip":
        r = requests.get(config["iprep_url"])
    if reptype == "domain":
        r = requests.get(config["domainrep_url"])

    return r.json()


def replist_delta(newlist, reptype):
    firstrun = False
    cf = config["cache"] + "/" + "et" + reptype + ".json"
    cftmp = cf + ".tmp"
    oldlist = {}
    replist = {}
    oldset = set()
    newset = set()
    adds = {}
    dels = {}

    try:
        s = os.stat(cf)
    except FileNotFoundError:
        firstrun = True

    if "ip" in newlist:
        del (newlist["ip"])
    if "domain" in newlist:
        del (newlist["domain"])

    for k, v in newlist.items():
        for ik, iv in v.items():
            iiv = int(iv)
            c = "Medium"
            if iiv < 100:
                c = "Low"
            elif iiv == 127:
                c = "High"
            newset.add(json.dumps([k, ik, c]))

    if firstrun:
        print("first run - pushing everything to MISP")
        adds = newset
    else:
        with open(cf) as f:
            oldlist = json.load(f)
            for k, v in oldlist.items():
                for ik, iv in v.items():
                    iiv = int(iv)
                    c = "Medium"
                    if iiv < 100:
                        c = "Low"
                    elif iiv == 127:
                        c = "High"
                    oldset.add(json.dumps([k, ik, c]))

        adds = newset - oldset
        dels = oldset - newset
        # print(len(adds))
        # print(adds)
        # print(len(dels))
        # print(dels)

    with open(cftmp, "wb") as f:
        f.write(json.dumps(newlist).encode("UTF-8"))
        f.flush()
        fsync(f.fileno())
    os.rename(cftmp, cf)

    return (adds, dels)


def create_attr_obj(ioc, cat, confidence, ioctype):
    attr = MISPAttribute()
    attr.disable_correlation = False
    if ioctype == "ip":
        attr.type = "ip-dst"
    elif ioctype == "domain":
        attr.type = "hostname"
    attr.category = "Network activity"
    attr.value = ioc
    attr.add_tag(cat + ":" + confidence)
    attr.add_tag(cat)
    attr.add_tag("expires:" + str(config["expires"]))
    if cat in config["nsmcats"]:
        if confidence in config["nsmcats"][cat].split(","):
            attr.add_tag("nsm")

    return attr


def add_attr_to_event(misp, ioc, cat, confidence, ioctype, e):
    a = create_attr_obj(ioc, cat, confidence, ioctype, e)
    if a:
        r = e.attributes.append(a)
        if "nsm" in a.tags:
            r = e.add_tag("nsm")
        r = misp.update_event(e)


def proc_chunk_adds(misp, adds, ioctype):
    print("proc_chunk_adds size {0}".format(len(adds)))
    event = create_event_obj(ioctype)
    for ioc in adds:
        ioc, cat, confidence = json.loads(ioc)
        attr = create_attr_obj(ioc, cat, confidence, ioctype)
        for tag in attr.tags:
            if tag.name == "nsm":
                event.add_tag("nsm")
        event.attributes.append(attr)
        event.add_tag(cat + ":" + confidence)
        event.add_tag(cat)
        event.add_tag("ET")

    event_json = event.to_json().replace("\n", "")
    r = misp.add_event(event_json)


def proc_chunk_adds_old(misp, adds, ioctype):
    # FIXME: events contain more than 1000 attributes
    # ^^ it makes no sense to search for an existing event, just create a new one
    # FIXME: only the first tag is used when creating an event
    # when an attribute with a different tag is added, event's tag is not updated
    # When no nsm tag in attributes anymore, remove the nsm tag from the parent event
    chunkts = datetime.utcnow()
    for ioc in adds:
        ioc, cat, confidence = json.loads(ioc)
        r = misp.search_index(tags=cat + ":" + confidence)
        if r:
            for event in r:
                for tag in event["EventTag"]:
                    if tag["Tag"]["name"] == cat + ":" + confidence:
                        e = misp.get_event(event["id"])
                        r = add_attr_to_event(misp, ioc, cat, confidence, ioctype, e)
        else:
            e = create_event_obj(ioc, cat, confidence, ioctype, chunkts)
            if e:
                eid = misp.add_event(e)
                if eid:
                    r = add_attr_to_event(misp, ioc, cat, confidence, ioctype, e)

    return


def proc_adds(misp, adds, ioctype):
    print("proc_adds size {0}".format(len(adds)))
    adds_list = list(adds)
    [
        proc_chunk_adds(misp, adds_list[i : i + 1000], ioctype)
        for i in range(0, len(adds_list), 1000)
    ]


def proc_dels(misp, dels, replist, reptype):
    dels = {'["86.35.15.215", "CnC", "77"]', '[" 109.99.228.58", "Scanner", "127"]'}
    for item in dels:
        ioc, cat, confidence = json.loads(item)
        attr = misp.search(
            controller="attributes",
            value=ioc,
            tag=cat + ":" + confidence,
            pythonify=True,
        )
        for a in attr:
            e = misp.get_event(a["event_id"])
            r = e.delete_attribute(a["id"])
            r = misp.update_event(e)

    # if no ioc-specific tags are left, remove the event (or just leave it around?)
    # if no attributes with cat under event, remove tag cat from event
    # if no attributes with cat:confidence under event, remove tag cat:confidence from event
    return


def create_event_obj(ioctype):
    chunkts = datetime.utcnow()

    misp_event = MISPEvent()
    misp_event.load_file(config["skeleton"])
    misp_event.threat_level_id = ThreatLevel.medium
    misp_event.analysis = Analysis.completed
    misp_event.distribution = Distribution.your_organisation_only
    misp_event.info = "Emerging Threats" + " | " + chunkts.strftime("%Y-%m-%d-%H:%M:%S")
    misp_event.set_date(chunkts)
    misp_event.published = True
    misp_event.uuid = str(uuid.uuid4())

    # misp_event.add_attribute(
    #    "campaign-name",
    #    misp_event.info,
    #    attribute="Attribution",
    #    comment="Campaign name",
    #    disable_correlation=True,
    # )
    misp_event.add_attribute(
        "text",
        "Emerging Threats",
        attribute="Internal reference",
        comment="Source",
        disable_correlation=True,
    )
    misp_event.add_attribute(
        "link",
        "http://threatintel.proofpoint.com/",
        attribute="External analysis",
        comment="URL",
        disable_correlation=True,
    )

    return misp_event


def main():
    log.level = logging.DEBUG
    log.info("Started and initialized")

    misp = ExpandedPyMISP(
        config["misp_api_url"], config["misp_api_key"], True, cert=config["certfile"]
    )

    for reptype in config["reptypes"]:
        replist = fetch_replist(reptype)
        (adds, dels) = replist_delta(replist, reptype)
        proc_adds(misp, adds, reptype)
        proc_dels(misp, dels, replist, reptype)


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
