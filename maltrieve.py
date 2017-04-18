#!/usr/bin/env python

# Copyright 2013 Kyle Maxwell
# Includes code from mwcrawler, (c) 2012 Ricardo Dias. Used under license.

# Maltrieve - retrieve malware from the source

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/

from __future__ import print_function

import argparse
import ConfigParser
import datetime
import hashlib
import json
import logging
import os
import re
import resource
import sys
import tempfile
from urlparse import urlparse
from hashlib import sha1
import sqlite3
import feedparser
import grequests
import magic
import requests
from bs4 import BeautifulSoup


def hashstr(thestr):
    hasher = sha1()
    hasher.update(thestr)
    return hasher.hexdigest()


class config(object):

    """ Class for holding global configuration setup """

    def __init__(self, args, filename='maltrieve.cfg'):
        self.configp = ConfigParser.ConfigParser(os.environ)
        self.configp.read(filename)

        if args.logfile or self.configp.get('Maltrieve', 'logfile'):
            if args.logfile:
                self.logfile = args.logfile
            else:
                self.logfile = self.configp.get('Maltrieve', 'logfile')
            logging.basicConfig(filename=self.logfile, level=logging.DEBUG,
                                format='%(asctime)s %(thread)d %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
        else:
            logging.basicConfig(level=logging.DEBUG,
                                format='%(asctime)s %(thread)d %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S')
        if args.proxy:
            self.proxy = {'http': args.proxy}
        elif self.configp.has_option('Maltrieve', 'proxy'):
            self.proxy = {'http': self.configp.get('Maltrieve', 'proxy')}
        else:
            self.proxy = None

        if self.configp.has_option('Maltrieve', 'User-Agent'):
            self.useragent = self.configp.get('Maltrieve', 'User-Agent')
        else:
            # Default to IE 9
            self.useragent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)"

        self.sort_mime = args.sort_mime

        if self.configp.has_option('Maltrieve', 'black_list'):
            self.black_list = self.configp.get('Maltrieve', 'black_list').strip().split(',')
        else:
            self.black_list = []

        if self.configp.has_option('Maltrieve', 'white_list'):
            self.white_list = self.configp.get('Maltrieve', 'white_list').strip().split(',')
        else:
            self.white_list = False

        if args.inputfile:
            self.inputfile = args.inputfile
        else:
            self.inputfile = None

        # make sure we can open the directory for writing
        if args.dumpdir:
            self.dumpdir = args.dumpdir
        elif self.configp.get('Maltrieve', 'dumpdir'):
            self.dumpdir = self.configp.get('Maltrieve', 'dumpdir')
        else:
            self.dumpdir = '/tmp/malware'

        # Create the dir
        if not os.path.exists(self.dumpdir):
            try:
                os.makedirs(self.dumpdir)
            except OSError:
                logging.error('Could not create %s, using default', self.dumpdir)
                self.dumpdir = '/tmp/malware'

        try:
            fd, temp_path = tempfile.mkstemp(dir=self.dumpdir)
        except OSError:
            logging.error('Could not open %s for writing, using default', self.dumpdir)
            self.dumpdir = '/tmp/malware'
        else:
            os.close(fd)
            os.remove(temp_path)

        logging.info('Using %s as dump directory', self.dumpdir)
        self.logheaders = self.configp.get('Maltrieve', 'logheaders')

        # TODO: Merge these
        self.cuckoo = args.cuckoo
        if self.configp.has_option('Maltrieve', 'cuckoo'):
            self.cuckoo = self.configp.get('Maltrieve', 'cuckoo')

	self.priority = args.priority
	if not self.priority and self.configp.has_option('Maltrieve', 'priority'):
		self.priority = self.configp.get('Maltrieve', 'priority')

        self.cuckoo_dist = args.cuckoo_dist
        if not self.cuckoo_dist and self.configp.has_option('Maltrieve', 'cuckoo_dist'):
            self.cuckoo_dist = self.configp.get('Maltrieve', 'cuckoo_dist')

        self.malshare_key = args.malshare_key
        if not self.malshare_key and self.configp.has_option('Maltrieve', 'malshare_key'):
            self.malshare_key = self.configp.get('Maltrieve', 'malshare_key')

    def check_proxy(self):
        if self.proxy:
            logging.info('Using proxy %s', self.proxy)
            my_ip = requests.get('http://ipinfo.io/ip', proxies=self.proxy).text
            logging.info('External sites see %s', my_ip)
            print('External sites see {ip}'.format(ip=my_ip))


# This gives cuckoo the URL instead of the file.
def upload_cuckoo(response, md5, cfg):
    if response:
        files = {'file': (md5, response.content)}
        url = cfg.cuckoo + "/tasks/create/file"
        headers = {'User-agent': 'Maltrieve'}
        try:
            response = requests.post(url, headers=headers, files=files)
            response_data = response.json()
            logging.info("Submitted %s to Cuckoo, task ID %d", md5, response_data["task_id"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to Cuckoo, will attempt local storage")
            return False
        else:
            return True


# This gives cuckoo the URL instead of the file.
def upload_cuckoo_dist(response, md5, cfg):
    if response:
        data = {'priority': int(cfg.priority)}
        files = {'file': (md5, response.content)}
        url = cfg.cuckoo_dist + "/api/task"
        headers = {'User-agent': 'Maltrieve'}
        try:
            response = requests.post(url, headers=headers, data=data, files=files)
            response_data = response.json()
            logging.info("Submitted %s to Cuckoo, task ID %d", md5, response_data["task_id"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to Cuckoo, will attempt local storage")
            return False
        else:
            return True


def save_malware(response, cfg):
    url = response.url
    data = response.content
    mime_type = magic.from_buffer(data, mime=True)
    print("Saving malware:", url, mime_type)
    if mime_type in cfg.black_list:
        logging.info('%s in ignore list for %s', mime_type, url)
        return False
    if cfg.white_list:
        if mime_type in cfg.white_list:
            pass
        else:
            logging.info('%s not in whitelist for %s', mime_type, url)
            return False

    # Hash and log
    md5 = hashlib.md5(data).hexdigest()
    logging.info("%s hashes to %s", url, md5)

    # Assume that external repo means we don't need to write to file as well.
    stored = False
    # Submit to external services

    # TODO: merge these
    if cfg.cuckoo:
        stored = upload_cuckoo(response, md5, cfg) or stored
    if cfg.cuckoo_dist:
        stored = upload_cuckoo_dist(response, md5, cfg) or stored
    # else save to disk
    if not stored:
        if cfg.sort_mime:
            # set folder per mime_type
            sort_folder = mime_type.replace('/', '_')
            if not os.path.exists(os.path.join(cfg.dumpdir, sort_folder)):
                os.makedirs(os.path.join(cfg.dumpdir, sort_folder))
            store_path = os.path.join(cfg.dumpdir, sort_folder, md5)
        else:
            store_path = os.path.join(cfg.dumpdir, md5)
        with open(store_path, 'wb') as f:
            f.write(data)
            logging.info("Saved %s to dump dir", md5)
    return True


def process_xml_list_desc(response):
    feed = feedparser.parse(response)
    urls = set()

    for entry in feed.entries:
        desc = entry.description
        url = desc.split(' ')[1].rstrip(',')
        if url == '':
            continue
        if url == '-':
            url = desc.split(' ')[4].rstrip(',')
        url = re.sub('&amp;', '&', url)
        if not re.match('http', url):
            url = 'http://' + url
        urls.add(url)

    return urls


def process_xml_list_title(response):
    feed = feedparser.parse(response)
    urls = set([re.sub('&amp;', '&', entry.title) for entry in feed.entries])
    return urls


def process_simple_list(response):
    urls = set([re.sub('&amp;', '&', line.strip()) for line in response.split('\n') if line.startswith('http')])
    return urls


def process_urlquery(response):
    soup = BeautifulSoup(response, "html.parser")
    urls = set()
    for t in soup.find_all("table", class_="test"):
        for a in t.find_all("a"):
            urls.add('http://' + re.sub('&amp;', '&', a.text))
    return urls


def process_malwaredb(response):
    # malwaredb.malekal.com
    return set([
        "http://malwaredb.malekal.com/files.php?file=%s" % (match,)
        for match in re.findall(r'files.php\?file=([a-f0-9]+)"', response, re.MULTILINE)
    ])


def process_malshare(response, cfg):
    # https://github.com/robbyFux/Ragpicker/blob/master/src/crawler/malShare.py
    api_key = cfg.malshare_key
    if not api_key:
        raise Exception("MalShare API key not configured, skip")
    return set([
        "http://api.malshare.com/sampleshare.php?action=getfile&api_key=%s&hash=%s" % (api_key, file_hash)
        for file_hash in response.split('\n')
    ])



def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


def setup_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--proxy",
                        help="Define HTTP proxy as address:port")
    parser.add_argument("-d", "--dumpdir",
                        help="Define dump directory for retrieved files")
    parser.add_argument("-i", "--inputfile", help="File of URLs to process")
    parser.add_argument("-l", "--logfile",
                        help="Define file for logging progress")
    parser.add_argument("-P", "--priority",
                        help="Cuckoo sample priority", default=2)
    parser.add_argument("-c", "--cuckoo",
                        help="Enable Cuckoo analysis", action="store_true", default=False)
    parser.add_argument("-C", "--cuckoo-dist",
                        help="Enable Distributed Cuckoo analysis", default=None)
    parser.add_argument("--malshare-key",
                        help="Malshare key", default=None)
    parser.add_argument("-s", "--sort_mime",
                        help="Sort files by MIME type", action="store_true", default=False)
    parser.add_argument("--config", help="Alternate config file (default maltrieve.cfg)")

    return parser.parse_args(args)


class MaltriveDatabase(object):
    def __init__(self, config):
        self.db = sqlite3.connect(config.dumpdir + '/malware.db')
        self.cur = self.db.cursor()
        self.cur.execute("""
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY,
    url_hash VARCHAR(10) NOT NULL,
    stamp DATETIME DEFAULT CURRENT_TIMESTAMP
)""")
        self.cur.execute("""
CREATE TABLE IF NOT EXISTS files (
    id INT PRIMARY KEY,
    file_hash VARCHAR(10) NOT NULL,
    stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    url_id INTEGER
)""")
        self.commit()

    def commit(self):
        self.db.commit()

    def insert_url(self, url):
        url_hash = hashstr(url)
        self.cur.execute("""
INSERT INTO urls (url_hash) VALUES (?)
        """, (url_hash,))

    def insert_file(self, hash):
        self.cur.execute("""
INSERT INTO files (file_hash) VALUES (?)
        """, (url,))

    def exists_url(self, url):
        self.cur.execute("""SELECT COUNT(id) FROM urls WHERE url_hash = ?""", (url,))
        res = self.cur.fetchone()
        if res:
            return res[0]

    def exists_file(self, hash):
        self.cur.execute("""SELECT COUNT(id) FROM files WHERE file_hash = ?""", (hash,))
        res = self.cur.fetchone()
        if res:
            return res[0]


def main():
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048, 2048))

    args = setup_args(sys.argv[1:])
    if args.config:
        cfg = config(args, args.config)
    else:
        cfg = config(args, 'maltrieve.cfg')
    cfg.check_proxy()

    database = MaltriveDatabase(cfg)

    print("Processing source URLs")

    # TODO: Replace with plugins
    source_urls = {
        'https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries': process_xml_list_desc,
        'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_xml_list_desc,
        'http://malc0de.com/rss/': process_xml_list_desc,
        'http://vxvault.net/URL_List.php': process_simple_list,
        'http://urlquery.net/': process_urlquery,
        'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list_title,
        'http://malwareurls.joxeankoret.com/normal.txt': process_simple_list,
        'http://malwaredb.malekal.com/': process_malwaredb
    }
    if cfg.malshare_key:
        source_urls['http://www.malshare.com/daily/malshare.current.txt'] = lambda x: process_malshare(x, cfg)
    headers = {'User-Agent': 'Maltrieve'}

    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg.proxy)
            for url in source_urls]
    source_lists = grequests.map(reqs)

    print("Processing found malware links")
    headers['User-Agent'] = cfg.useragent
    malware_urls = set()
    for response in source_lists:
        if hasattr(response, 'status_code') and response.status_code == 200:            
            found_urls = source_urls[response.url](response.text)
            malware_urls.update(found_urls)

    if cfg.inputfile:
        with open(cfg.inputfile, 'rb') as f:
            moar_urls = list(f)
        malware_urls.update(moar_urls)

    malware_urls = [url for url in malware_urls if not database.exists_url(url)]

    print("Downloading %d malware samples" % (len(malware_urls),))    
    reqs = [grequests.get(url, timeout=60, headers=headers, proxies=cfg.proxy)
	    for url in malware_urls]
    for chunk in chunker(reqs, 5):
        for url in chunk:
            print("  - ", url)
        malware_downloads = grequests.map(chunk)
        for each in malware_downloads:
            if not each or each.status_code != 200:
                continue
            if save_malware(each, cfg):
                database.insert_url(each.url)
        database.commit()


    print("Completed downloads")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit()
