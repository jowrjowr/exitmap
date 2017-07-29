#!/usr/bin/env python2

# Copyright 2013-2017 Eric Gisse <eric.gisse@gmail.com>
#
# This file is part of exitmap.
#
# exitmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# exitmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with exitmap.  If not, see <http://www.gnu.org/licenses/>.

"""
Module to detect SSL MITM
"""

import sys
import json
import logging
import socks
import socket
import util
import torsocks
import error
import ssl
from oscrypto import tls
from certvalidator import CertificateValidator
from stem import Signal
from stem.control import Controller
from error import SOCKSv5Error
from contextlib import closing
import stem.descriptor.server_descriptor as descriptor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
# setup logging

log = logging.getLogger(__name__)

details = dict()
details['github.com'] = { 'port': 443 }
details['gitlab.com'] = { 'port': 443 }
details['bitbucket.com'] = { 'port': 443 }
details['facebook.com'] = { 'port': 443 }
details['google.com'] = { 'port': 443 }
details['reddit.com'] = { 'port': 443 }
details['gmail.com'] = { 'port': 443 }
details['accounts.google.com'] = { 'port': 443 }
details['etrade.com'] = { 'port': 443 }

# build the destinations array that exitmap needs

destinations = []
for host in details:
    destinations.append((host, details[host]['port']))

def setup():
    """
    Perform one-off setup tasks, i.e., download reference files.
    """

    log.info('obtaining ssl cert information for destinations')

    for host, port in destinations:
        # obtain the clear-wire ssl information that will be used for comparison
        ipv4 = socket.gethostbyname(host)
        address = '%s:%s' % (host, port)

        try:
            sock = socket.create_connection((host, port))
        except socket.error as err:
            log.info('socket connection error to %s: %s' % (address, err))
            sys.exit(1)

        relay = 'clear wire'
        cert_pem, version = dump_ssl(sock, host, port, relay)
        details[host]['cert_pem'] = cert_pem
        details[host]['ssl_version'] = version

def dump_ssl(sock, host, port, relay):
    # do the actual work of dumping the ssl certificate

    log.debug('retrieving ssl cert from %s:%s over %s' % (host, port, relay))

    addr = host, port
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # these are horribly insecure options, but maximally permissive.
        # see matrix in https://docs.python.org/2/library/ssl.html#ssl.wrap_socket
        #
        # if server has a garbage configuration, that's not our problem.
        context.options = ssl.PROTOCOL_SSLv23
        context.verify_mode = ssl.CERT_OPTIONAL
        context.check_hostname = False
        sslsock = context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLError as err:
        log.debug('SSL error with %s:%s over %s: %s' % (host, port, relay, err))
        return None, None

    version = sslsock.version()
    log.debug('SSL version for %s:%s: %s, negotiated over %s' % (host, port, version, relay))

    # get the ssl cert

    cert = sslsock.getpeercert(True)
    cert = ssl.DER_cert_to_PEM_cert(cert)

    # close up shop
    # unclear if i need to unwrap() or not
    sock.close()

    return cert, version

def test_ssl(exit_desc):

    """
    is you or is you not MITMing my SSL?
    """

    exit_url = util.exiturl(exit_desc.fingerprint)
    AF_INET = socket.AF_INET
    SOCK_STREAM = socket.SOCK_STREAM

    for host, port in destinations:

        # work through each test target

        cert_pem = details[host]['cert_pem']
        ssl_version = details[host]['ssl_version']

        if cert_pem == None:
            continue

        # setup the tor connection

        sock = torsocks.torsocket()
        sock.settimeout(10)

        # resolve the ip over tor, like it normally would for a client.

        try:
            ipv4 = sock.resolve(host)
            log.debug("destination %s resolves to: %s" % (host, ipv4))
        except SOCKSv5Error as err:
            log.debug("%s did not resolve broken domain because: %s." % (exit_url, err))
            return
        except socket.timeout as err:
            log.debug("Socket over exit relay %s timed out: %s" % (exit_url, err))
            return
        except Exception as err:
            log.debug("Could not resolve domain because: %s" % err)
            return
        finally:
            sock.close()

        # torsocks does not seem to like recycling?

        sock = torsocks.torsocket()
        sock.settimeout(10)

        try:
            address = (ipv4, port)
            sock.connect(address)
        except socks.GeneralProxyError as err:
            log.info('unable to connect to tor socks5 proxy: %s' % (err))
            continue

        relay = 'over relay %s' % (exit_desc.fingerprint)
        tor_cert_pem, tor_ssl_version = dump_ssl(sock, host, port, relay)

        if tor_cert_pem == None:
            continue
        # process the certs
        cert = x509.load_pem_x509_certificate(str(cert_pem), default_backend())
        tor_cert = x509.load_pem_x509_certificate(str(tor_cert_pem), default_backend())

        # do the matching

        if not ssl_version == tor_ssl_version:
            log.critical('ssl version mismatch over exit relay %s. clear wire value: %s, over tor value: %s' % (exit_desc.fingerprint, ssl_version, tor_ssl_version))

            # not SURE of the implications of this yet

            print(cert_pem)
            print(tor_cert_pem)
        else:
            log.debug('ssl negotiated version match for %s:%s (%s) over exit relay %s' % (host, port, ipv4, exit_desc.fingerprint))


        if cert == tor_cert:
            log.debug('ssl key match for %s:%s (%s) over exit relay %s' % (host, port, ipv4, exit_desc.fingerprint))
            continue

        # the certs do not match

        log.critical('ssl certificate mismatch over exit relay %s. clear wire fingerprint: %s, over tor fingerprint: %s' % (exit_desc.fingerprint, cert.fingerprint, tor_cert.fingerprint))

        print(tor_cert_pem)
def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    test if the exit relay is playing games with ssl
    """

    run_python_over_tor(test_ssl, exit_desc)

if __name__ == "__main__":
    log.critical("Module can only be run over Tor, not stand-alone.")
    sys.exit(1)

