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
Module to detect ssh mitm
"""

import sys
import logging
import paramiko
import socket

from torsocks import torsocket
from util import exiturl
from error import SOCKSv5Error

# setup logging

log = logging.getLogger(__name__)

# nobody cares if paramiko successfully connects. not what we are looking for.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

details = dict()
details['github.com'] = { 'port': 22 }
details['gitlab.com'] = { 'port': 22 }
details['bitbucket.com'] = { 'port': 22 }

# build the destinations array that exitmap needs

destinations = []
for host in details:
    destinations.append((host, details[host]['port']))

def setup():
    """
    Perform one-off setup tasks, i.e., download reference files.
    """

    log.info('obtaining ssh key information for destinations')

    for host, port in destinations:

        log.info('getting key for %s' % (host))

        ipv4 = socket.gethostbyname(host)
        address = '%s:%s' % (ipv4, port)

        try:
            transport = paramiko.transport.Transport(address)
        except paramiko.SSHException as err:
            log.info('ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            return

        try:
            transport.start_client()
        except EOFError as e:
            log.info('unknown ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            return
        except paramiko.SSHException as err:
            log.info('ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            return

        try:
            key = transport.get_remote_server_key()
            version = transport.remote_version
        except paramiko.SSHException as err:
            log.info('unable to retreive remote key for %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            return
        finally:
            transport.close()


        key_name = key.get_name()
        key_base64 = key.get_base64()


        log.debug('ssh key (clear) name for %s:%s (%s): %s' % (host, port, ipv4, key_name))
        log.debug('ssh key (clear) for %s:%s (%s): %s' % (host, port, ipv4, key_base64))
        log.debug('ssh version (clear) for %s:%s (%s): %s' % (host, port, ipv4, version))

        details[host]['version'] = version
        details[host]['key_name'] = key_name
        details[host]['key_base64'] = key_base64

def test_ssh(exit_desc):

    """
    is you or is you not MITMing my ssh?
    """
    exit_fp = exit_desc.fingerprint
    exit_url = exiturl(exit_fp)

    log.debug('testing exit %s' % (exit_fp))

    fail_count = 0

    for host, port in destinations:

        # construct the tor socket

        sock = torsocket()
        sock.settimeout(10)

        # resolve the ip over tor, like it normally would for a client.

        try:
            ipv4 = sock.resolve(host)
            log.debug("destination %s resolves to: %s" % (host, ipv4))
        except SOCKSv5Error as err:
            log.debug("%s did not resolve broken domain because: %s." % (exit_url, err))
            fail_count += 1
            continue
        except socket.timeout as err:
            log.debug("Socket over exit relay %s timed out: %s" % (exit_url, err))
            fail_count += 1
            continue
        except Exception as err:
            log.debug("Could not resolve domain because: %s" % err)
            fail_count += 1
            continue
        finally:
            sock.close()

        # connect to the actual target
        sock = torsocket()
        sock.settimeout(10)

        address = (ipv4, port)
        sock.connect(address)

        # get the over-tor key information
        try:
            client = paramiko.transport.Transport(sock)
        except EOFError as err:
            log.info('unknown ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            fail_count += 1
            continue
        except paramiko.SSHException as err:
            log.info('ssh exception conneting to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            fail_count += 1
            continue

        try:
            client.start_client()
        except EOFError as err:
            log.info('unknown ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            fail_count += 1
            continue
        except paramiko.SSHException as err:
            log.info('ssh connection error to %s:%s (%s) over exit relay %s: %s' % (host, port, ipv4, exit_fp, err))
            fail_count += 1
            continue

        tor_version = client.remote_version
        key = client.get_remote_server_key()
        client.close()
        sock.close()

        tor_key_name = key.get_name()
        tor_key_base64 = key.get_base64()
        log.debug('ssh key (tor) name for %s:%s (%s): %s' % (host, port, ipv4, tor_key_name))
        log.debug('ssh key (tor) for %s:%s (%s): %s' % (host, port, ipv4, tor_key_base64))
        log.debug('ssh version (tor) for %s:%s (%s): %s' % (host, port, ipv4, tor_version))

        # do the matching

        version = details[host]['version']
        key_name = details[host]['key_name']
        key_base64 = details[host]['key_base64']

        if not key_name == tor_key_name:
            log.critical('tor ssh key name mismatch for %s:%s (%s) over exit relay %s clear wire value: %s, over tor value: %s' % (host, port, ipv4, exit_fp, key_name, tor_key_name))
        else:
            log.debug('tor ssh key name match for %s:%s (%s) over exit relay %s' % (host, port, ipv4, exit_fp))
        if not key_base64 == tor_key_base64:
            log.critical('tor ssh key mismatch for %s:%s (%s) over exit relay %s' % (host, port, ipv4, exit_fp))
            log.critical('clear wire key: %s' % (key_base64))
            log.critical('clear wire version: %s' % (version))
            log.critical('over tor key: %s' % (tor_key_base64))
            log.critical('over tor version: %s' % (tor_version))
            log.info('atlas link: https://atlas.torproject.org/#details/%s' % (exit_fp))
        else:
            log.debug('tor ssh key match for %s:%s (%s) over exit relay %s' % (host, port, ipv4, exit_fp))

    # if EVERY host is unable to be connected to, this could indicate a broken/misconfigured exit

    if fail_count == len(details):
        log.warning('exit %s appears to be having issues connecting over ssh. misconfiguration?' % (exit_fp))
        log.info('atlas link: https://atlas.torproject.org/#details/%s' % (exit_fp))

    if fail_count > 0:
        log.warning('%s of %s ssh connections have failed over exit %s' % (fail_count, len(details), exit_fp))

def probe(exit_desc, run_python_over_tor, run_cmd_over_tor, **kwargs):
    """
    test if the exit relay is playing games with ssh
    """

    run_python_over_tor(test_ssh, exit_desc)

if __name__ == "__main__":
    log.critical("Module can only be run over Tor, not stand-alone.")
    sys.exit(1)
