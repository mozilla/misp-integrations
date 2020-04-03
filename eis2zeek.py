#!/usr/bin/env python3
import argparse
import logging
from yaml import Loader, load, dump
from sys import argv, stderr
from os import environ, fsync, stat, rename, path, close
from tempfile import mkstemp
from logging.handlers import SysLogHandler
import sys
import os
import yaml
import json
from agithub.GitHub import GitHub
from git import Repo
from giturlparse import parse
from retrying import retry
from tempfile import NamedTemporaryFile


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
        cfpath = argv[0].replace('.py', '.yml')
    with open(cfpath, "r") as configyaml:
        cf = load(configyaml, Loader=Loader)

    config['debug'] = cf.get("debug", False)
    config['username'] = cf.get('username', '<ETINTELAPIKEY>')
    config['password'] = cf.get('password', '<ETINTELAPIKEY>')
    config['upstream_url'] = cf.get('upstream_url')
    config['expires'] = cf.get('expires', '3600')
    config['repodir'] = cf.get('repodir')
    config['inteldir'] = cf.get('inteldir')
    config['intelfile'] = cf.get('intelfile')
    config['wlfile'] = cf.get('wlfile', 'whitelist.yml')
    config['proxy'] = cf.get('proxy', None)
    config['reponame'] = cf.get('reponame')
    config['zeekrepopath'] = cf.get('zeekrepopath')

    with open(config['wlfile'], 'r') as wl:
        wlmap = wl.read()
        config['whitelist'] = yaml.load(wlmap)
        del wlmap

    return config


def whitelisted(ioc):
    if ioc in config['whitelist']:
        return True


def write_intel():
    with open(
        os.path.join(config['repodir'], config['reponame'], config['zeekrepopath'], config['intelfile']), mode='rb'
    ) as src:
        data = src.read()

    with NamedTemporaryFile(
        delete=False, mode='w+b', dir=config['inteldir'], prefix=config['intelfile'] + '.', suffix='.tmp'
    ) as tmp:
        r = tmp.write(data)

        tmp.flush()
        fsync(tmp.fileno())
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
    if (ratio > 0.1) and (ratio < 1000):
        rename(newpath, oldpath)
    else:
        log.error("Huge feed size difference, preserving old data")


def fetch_intel():
    parsed_url = parse(config['upstream_url'])
    build_url = 'https://{0}:{1}@{2}'.format(config['username'], config['password'], config['upstream_url'])
    repo_dir_root = config['repodir']
    repo_dir = os.path.expanduser(os.path.join(config['repodir'], parsed_url.repo))
    if os.path.isdir(repo_dir):
        cloned_repo = Repo(repo_dir)
    else:
        cloned_repo = Repo.clone_from(build_url, repo_dir)
    cloned_repo.remotes.origin.fetch()
    cloned_repo.remotes.origin.pull()


def main():
    fetch_intel()
    write_intel()


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
