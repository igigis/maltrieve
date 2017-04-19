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

from gevent import monkey
monkey.patch_all()

from argparse import Namespace, ArgumentParser
import ConfigParser
import datetime
import hashlib
import json
import logging
import os
import random
import re
import resource
import sys
import tempfile
try:
    from czipfile import ZipFile
except ImportError:
    logging.warning("Using slow Python standard zipfile")
    from zipfile import ZipFile

import gevent.pool
import grequests
from urlparse import urlparse
import sqlite3
import feedparser
import magic
import requests
from bs4 import BeautifulSoup


def hashstr(thestr, hashfn=hashlib.sha1):
    hasher = hashfn()
    hasher.update(str(thestr))
    return hasher.hexdigest()


def check_proxy(opts):
    if opts.proxy:
        logging.info('Using proxy %s', opts.proxy)
        my_ip = requests.get('http://ipinfo.io/ip', proxies=opts.proxy).text
        logging.info('External sites see %s', my_ip)
        print('External sites see {ip}'.format(ip=my_ip))


# This gives cuckoo the URL instead of the file.
def upload_cuckoo(data, sample, cfg):
    if data:
        files = {'file': (sample.file_md5, data)}
        url = cfg.cuckoo + "/tasks/create/file"
        data = dict(
            priority=cfg.priority,
            custom=json.dumps(source=sample.source),
        )
        headers = {'User-agent': 'Maltrieve'}
        try:
            response = requests.post(url, data=data, headers=headers, files=files)
            try:
                response_data = response.json()
            except ValueError:
                logging.exception("While decoding %s", response.text)
            else:
                logging.info("Submitted %s to Cuckoo, task ID %d", sample.file_md5, response_data["task_id"])
        except requests.exceptions.ConnectionError:
            logging.info("Could not connect to Cuckoo, will attempt local storage")
            return False
        else:
            return True


def process_xml_list_desc(response, source):
    feed = feedparser.parse(response)
    urls = list()

    for entry in feed.entries:
        desc = entry.description
        try:
            if "status: offline" in desc:
                continue
            try:
                file_md5 = re.search(r'MD5( hash)?: ([a-f0-9]{32})', desc).group(2)
            except AttributeError:
                file_md5 = None
            url = desc.split(' ')[1].rstrip(',')
            if url == '':
                continue
            if url == '-':
                url = desc.split(' ')[4].rstrip(',')
            url = re.sub('&amp;', '&', url)
            if not re.match('http', url):
                url = 'http://' + url
            urls.append(Namespace(url=url, source=source, file_md5=file_md5))
        except Exception:
            logging.exception("Error parsing %s description: %s", source, desc)

    return urls


def process_malwaredomainlist(response):
    return process_xml_list_desc(response, 'malwaredomainlist')

def process_zeustracker(response):
    return process_xml_list_desc(response, 'zeustracker')

def process_malc0de(response):
    return process_xml_list_desc(response, 'malc0de')

def process_xml_list_title(response):
    feed = feedparser.parse(response)
    return [re.sub('&amp;', '&', entry.title) for entry in feed.entries]

def process_vxvault(response):
    return process_simple_list(response, 'vxvault')

def process_malwareurls(response):
    return process_simple_list(response, 'malwareurls')

def process_minotaur(response):
    return process_simple_list(response, 'minotaur')


def process_simple_list(response, source):
    results = list()
    for line in response.split('\n'):
        if not line.startswith('http'):
            continue
        line = re.sub('&amp;', '&', line.strip())   
        results.append(
            Namespace(
                source=source,
                url=line))
    return results


def process_dasmalwerk(response):
    response = json.loads(response)
    return [
        Namespace(
            url="http://dasmalwerk.eu/zippedMalware/" + item['Filename'] + ".zip",
            source='dasmalwerk')
        for item in response['items']
        if 'Filename' in item
    ]


def process_urlquery(response):
    soup = BeautifulSoup(response, "html.parser")
    urls = list()
    for t in soup.find_all("table", class_="test"):
        for a in t.find_all("a"):
            urls.append(
                Namespace(
                    source='urlquery',
                    url='http://' + re.sub('&amp;', '&', a.text)))
    return urls


def process_malwaredb(response):
    # malwaredb.malekal.com
    return [
        Namespace(
            source='malwaredb',
            file_md5=match,
            url="http://malwaredb.malekal.com/files.php?file=%s" % (match,))
        for match in re.findall(r'files.php\?file=([a-f0-9]+)"', response, re.MULTILINE)
    ]


def process_malshare(response, cfg):
    # https://github.com/robbyFux/Ragpicker/blob/master/src/crawler/malShare.py
    api_key = cfg.malshare
    if not api_key:
        raise Exception("MalShare API key not configured, skip")
    return [
        Namespace(
            source='malshare',
            url="http://api.malshare.com/sampleshare.php?action=getfile&api_key=%s&hash=%s" % (api_key, file_hash),
            file_md5=file_hash)
        for file_hash in response.split('\n')
    ]


def chunker(seq, size):
    return (seq[pos:pos + size] for pos in xrange(0, len(seq), size))


def setup_args(args):
    parser = ArgumentParser()
    parser.add_argument('-q', '--quiet', action='store_true',
                        help="Don't print results to console")
    parser.add_argument('-v', '--verbose', action='store_const',
                        dest="loglevel", const=logging.INFO,
                        help="Log informational messages")
    parser.add_argument('--debug', action='store_const', dest="loglevel",
                        const=logging.DEBUG, default=logging.WARNING,
                        help="Log debugging messages")
    parser.add_argument("-p", "--proxy",
                        help="Define HTTP proxy, e.g. socks5://localhost:9050")
    parser.add_argument("-d", "--dumpdir", default="/tmp/maltrieve",
                        help="Define dump directory for retrieved files")
    parser.add_argument("-i", "--inputfile", nargs='*', help="Text file with URLs to retrieve")
    parser.add_argument("-b", "--blacklist", help="Comma separated mimetype blacklist")
    parser.add_argument("-w", "--whitelist", help="Comma separated mimetype whitelist")
    parser.add_argument("-P", "--priority",
                        help="Cuckoo sample priority", default=2)
    parser.add_argument("-c", "--cuckoo", metavar='URL', help="Cuckoo API")
    parser.add_argument('-U', '--useragent', help='HTTP User agent', default="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)")
    parser.add_argument("--malshare",
                        help="Malshare key", default=None)
    parser.add_argument("-t", "--timeout", type=int, default=20,
                        help="HTTP request/response timeout (default 20)")
    parser.add_argument("-N", "--concurrency", type=int, default=5,
                        help="HTTP request/response concurrency (default 5)")
    parser.add_argument("-s", "--sort_mime",
                        help="Sort files by MIME type", action="store_true", default=False)
    parser.add_argument("-L", "--local",
                        help="Don't search external sources", action="store_true", default=False)
    parser.add_argument("-z", "--zip", metavar="FILE", nargs='*')
    return parser.parse_args(args)


def check_options(opts):
    logging.basicConfig(level=opts.loglevel)

    check_proxy(opts)

    if opts.proxy:
        opts.proxy = {'http': opts.proxy, 'https': opts.proxy}

    opts.blacklist = opts.blacklist.strip().split(',') if opts.blacklist else []
    opts.whitelist = opts.whitelist.strip().split(',') if opts.whitelist else []

    if not os.path.exists(opts.dumpdir):
        try:
            os.makedirs(opts.dumpdir)
        except OSError:
            logging.error('Could not create %s, using default', opts.dumpdir)
            sys.exit(111)
    try:
        fd, temp_path = tempfile.mkstemp(dir=opts.dumpdir)
    except OSError:
        logging.error('Could not open %s for writing, using default', opts.dumpdir)
        sys.exit(112)
    else:
        os.close(fd)
        os.remove(temp_path)


class MaltriveDatabase(object):
    def __init__(self, config):
        self.db = sqlite3.connect(config.dumpdir + '/malware.db')
        self.cur = self.db.cursor()
        self.cur.execute("""
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY,
    source VARCHAR(128) NOT NULL,
    mime_type VARCHAR(64) NOT NULL,
    url VARCHAR(512) NOT NULL,
    url_sha1 VARCHAR(10) NOT NULL,
    file_sha256 VARCHAR(10) NOT NULL,
    file_sha1 VARCHAR(10) NOT NULL,
    file_md5 VARCHAR(10) NOT NULL,
    stamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)""")
        self.commit()

    def commit(self):
        self.db.commit()

    def only_unknown(self, sample_list):
        return [sample for sample in sample_list
                if not self.exists(sample)]

    def normalise(self, sample):
        if not getattr(sample, 'url_sha1', None):
            sample.url_sha1 = hashstr(sample.url, hashlib.sha1)

    def insert(self, sample):
        self.normalise(sample)
        pairs = [(key, value) for key, value in sample.__dict__.items()
                 if key[0] != '_']
        keys = ','.join([x[0] for x in pairs])
        placeholders = ','.join(['?' for _ in pairs])
        values = [x[1] for x in pairs]
        sql = "INSERT INTO entries (%s) VALUES (%s)" % (keys, placeholders)
        self.cur.execute(sql, values)

    def exists(self, sample):
        self.normalise(sample)
        search_keys = ('url_sha1', 'file_sha1', 'file_md5')
        wheres = ' OR '.join([
            "%s = ?" % (key,)
            for key in sample.__dict__.keys()
            if key in search_keys
        ])
        if not len(wheres):
            raise RuntimeError("No searchable fields in sample:", sample)

        sql = "SELECT COUNT(id) FROM entries WHERE " + wheres
        values = [value for key, value in sample.__dict__.items()
                  if key in search_keys]
        self.cur.execute(sql, values)
        res = self.cur.fetchone()
        return int(res[0]) > 0


def zip_tryopen(handle, filename):
    passwords = [None, 'infected', 'malware']
    last_error = None
    while len(passwords):
        pwd = passwords[0]
        try:
            entry = handle.open(filename, pwd=pwd)
        except RuntimeError as ex:
            last_error = ex
        else:
            last_error = None
            if pwd is not None:
                handle.setpassword(pwd)
            break
        passwords = passwords[1:]
    if last_error:
        raise ex
    assert entry is not None
    return entry


class Maltrieve(object):
    def __init__(self, args):
        self.opts = setup_args(args)
        check_options(self.opts)
        self.database = MaltriveDatabase(self.opts)

    def save_malware(self, sample, data):
        if 'mime_type' not in sample:
            sample.mime_type = magic.from_buffer(data, mime=True)
        logging.info("Saving malware: %s (%s)", sample.url, sample.mime_type)

        if sample.mime_type in self.opts.blacklist:
            logging.info('%s in ignore list for %s', sample.mime_type, sample.url)
            return None
        if self.opts.whitelist:
            if sample.mime_type in self.opts.whitelist:
                pass
            else:
                logging.info('%s not in whitelist for %s', sample.mime_type, sample.url)
                return None

        if not getattr(sample, 'file_md5', None):
            sample.file_md5 = hashstr(data, hashlib.md5)
        if not getattr(sample, 'file_sha1', None):
            sample.file_sha1 = hashstr(data, hashlib.sha1)
        if not getattr(sample, 'file_sha256', None):
            sample.file_sha256 = hashstr(data, hashlib.sha256)

        if self.database.exists(sample):
            logging.info("Sample already exists")
            return None

        # Assume that external repo means we don't need to write to file as well.
        stored = False
        if self.opts.cuckoo:
            stored = upload_cuckoo(data, sample, self.opts) or stored
        # else save to disk
        if not stored:
            if self.opts.sort_mime:
                # set folder per mime_type
                sort_folder = sample.mime_type.replace('/', '_')
                if not os.path.exists(os.path.join(self.opts.dumpdir, sort_folder)):
                    os.makedirs(os.path.join(self.opts.dumpdir, sort_folder))
                store_path = os.path.join(self.opts.dumpdir, sort_folder, sample.file_md5)
            else:
                store_path = os.path.join(self.opts.dumpdir, sample.file_md5)
            with open(store_path, 'wb') as handle:
                handle.write(data)
                logging.info("Saved %s to dump dir", sample.file_md5)

        self.database.insert(sample)
        return sample

    def _find_remote(self):
        source_urls = {
            "http://dasmalwerk.eu/api/": process_dasmalwerk,
            'http://malc0de.com/rss/': process_malc0de,
            'https://zeustracker.abuse.ch/monitor.php?urlfeed=binaries': process_zeustracker,
            'http://www.malwaredomainlist.com/hostslist/mdl.xml': process_malwaredomainlist,
            'http://vxvault.net/URL_List.php': process_vxvault,
            'http://urlquery.net/search.php?q=%25&max=50': process_urlquery,
            'http://malwareurls.joxeankoret.com/normal.txt': process_malwareurls,
            'http://malwaredb.malekal.com/': process_malwaredb,
            'http://minotauranalysis.com/raw/urls': process_minotaur,

            # XXX: disabled - requires registration of user agent
            #'http://support.clean-mx.de/clean-mx/rss?scope=viruses&limit=0%2C64': process_xml_list_title,
        }
        if self.opts.malshare:
            source_urls['http://www.malshare.com/daily/malshare.current.txt'] = lambda x: process_malshare(x, self.opts)

        logging.info("Retrieving URLs from %d sources", len(source_urls))
        headers = {'User-Agent': 'Maltrieve'}
        reqs = [grequests.get(url, timeout=self.opts.timeout, headers=headers, proxies=self.opts.proxy)
                for url in source_urls]
        source_lists = grequests.map(reqs)
        
        sample_list = list()
        for response in source_lists:
            if hasattr(response, 'status_code') and response.status_code == 200:            
                found_urls = source_urls[response.url](response.text)
                if not len(found_urls):
                    logging.warning('Source found no samples at url: %r', response.url)
                else:
                    logging.info("Found %d samples at url: %r", len(found_urls), response.url)
                sample_list.extend(found_urls)
        return sample_list

    def _find_local(self):
        """
        Use local sources, e.g. input files of URLs and zip files, to import
        malware samples.
        """
        sample_list = list()

        if self.opts.inputfile:
            for inputfile in self.opts.inputfile:
                with open(inputfile, 'rb') as handle:
                    found_samples = process_simple_list(handle.read())
                    if not len(found_samples):
                        logging.warning("Found no samples in local file %r", inputfile)
                    else:
                        logging.info("Found %d samples in local file %r", len(found_samples), inputfile)
                        sample_list.extend(found_samples)

        if self.opts.zip:
            for zip_filename in self.opts.zip:
                handle = ZipFile(zip_filename, 'r')
                found_samples = list()
                for entry in handle.infolist():
                    url = '://'.join([os.path.basename(zip_filename), entry.filename])
                    found_samples.append(
                        Namespace(url=url,
                                  url_sha1=hashstr(url, hashlib.sha1),
                                  _zip_handle=handle,
                                  _zip_filename=entry.filename,
                                  _read=lambda x: zip_tryopen(x._zip_handle, x._zip_filename).read(),
                                  source='zip'))
                if not len(found_samples):
                    logging.warning("Found no samples in local zip file %r", zip_filename)
                else:
                    logging.info("Found %d samples in local file %r", len(found_samples), zip_filename)
                    sample_list.extend(found_samples)

        return sample_list

    def find_samples(self):
        sample_list = list()
        sample_list.extend(self._find_local())
        if not self.opts.local:
            sample_list.extend(self._find_remote())
        return sample_list

    def import_sample(self, sample):
        logging.info("Importing sample: %r", sample.url)
        readfn = getattr(sample, '_read', None)
        if readfn:
            assert callable(readfn)
            data = readfn(sample)
        else:
            headers = {'User-Agent': self.opts.useragent}
            try:
                resp = requests.get(sample.url, headers=headers,
                                    proxies=self.opts.proxy,
                                    timeout=self.opts.timeout)
                if resp.status_code != 200:
                    return None
                data = resp.content
            except Exception:
                return None
        if data:
            return self.save_malware(sample, data)

    def import_samples(self, sample_list):
        # Filter out known/duplicate samples
        len_before = len(sample_list)
        sample_list = self.database.only_unknown(sample_list)
        logging.info("Importing %d malware samples (%d duplicates)",
                     len(sample_list), len_before - len(sample_list))
        pool = gevent.pool.Pool(self.opts.concurrency)
        for idx, sample in enumerate(sample_list):
            pool.add(gevent.spawn(self.import_sample, sample))
            if idx % 10 == 0:
                self.database.commit()
        pool.join()
        self.database.commit()


def main():
    resource.setrlimit(resource.RLIMIT_NOFILE, (2048, 2048))
    maltrieve = Maltrieve(sys.argv[1:])
    try:
        sample_list = maltrieve.find_samples()
        if not len(sample_list):
            logging.error('No samples to download - exiting')
            return 100
        maltrieve.import_samples(sample_list)
    finally:
        maltrieve.database.commit()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
