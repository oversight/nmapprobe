from distutils.log import error
import subprocess
import xml.etree.ElementTree as ET
import asyncio
import logging
import time

from .base import Base, SEMAPHORE
from .exceptions import UnresolvableException
from .utils import check_response
from datetime import datetime
from typing import List


def cert_props_to_dict(node, query, prefix):
    return {
        prefix + elem.attrib['key']: elem.text for elem in node.findall(query)
    }


HTTPS = 443
POP3_SSL = 995
IMAP_SSL = 993
SMTP_SSL = 465
RDP_SSL = 3389
FTP_SSL_A = 989
FTP_SSL_B = 990
LDAP_SLL = 636
WINRM_SSL = 5986


KNOWN_SSL_PORTS = (
    HTTPS,
    POP3_SSL,
    IMAP_SSL,
    SMTP_SSL,
    RDP_SSL,
    FTP_SSL_A,
    FTP_SSL_B,
    LDAP_SLL,
    WINRM_SSL
)


class CheckCertificates(Base):

    interval = 3600  # TODO ???
    required = False
    type_name = 'certificates'

    @staticmethod
    def on_item(itm):
        return {
            'name': itm.name,  # (str)
        }

    @staticmethod
    def _parse_cert_info(node):
        '''
        Parse certificate header info
        :param node: Element with certificate info
        :return: dict of certificate info
        '''
        if not node:
            return {}

        def get_text(table=None, elem=None, allow_none=False):
            pth = f"table[@key='{table}']/elem[@key='{elem}']" if elem \
                else f"elem[@key='{table}']"
            nod = node.find(pth)
            if nod is None:
                if allow_none:
                    return None
                else:
                    raise Exception(f'unable to find {pth}')
            return nod.text

        not_after = datetime.strptime(
            get_text('validity', 'notAfter')[:19],
            '%Y-%m-%dT%H:%M:%S'
        )
        dct = {
            'subject': '/'.join(map(
                lambda elem: f'{elem.attrib["key"]}={elem.text}',
                node.findall("table[@key='subject']/elem")
            )),
            'issuer': '/'.join(map(
                lambda elem: f'{elem.attrib["key"]}={elem.text}',
                node.findall("table[@key='issuer']/elem")
            )),
            'pubkey_type': get_text('pubkey', 'type'),
            'pubkey_bits': get_text('pubkey', 'bits'),
            'algorithm': get_text('sig_algo', allow_none=True),
            'md5': get_text('md5'),
            'sha1': get_text('sha1'),
            'valid_not_before': datetime.strptime(
                get_text('validity', 'notBefore')[:19],
                '%Y-%m-%dT%H:%M:%S'
            ),
            'valid_not_after': not_after,
            'expired': not_after < datetime.now(),
            'expiresIn': (not_after - datetime.now()).total_seconds()
        }
        dct.update(**cert_props_to_dict(
            node,
            "table[@key='subject']/elem",
            'certificate_'
        ))
        dct.update(**cert_props_to_dict(
            node,
            "table[@key='issuer']/elem",
            'issuer_'
        ))
        return dct

    @staticmethod
    def _parse_protocols(node, host, port):
        '''
        :param node: Element with ciphers list
        :param host: hostname
        :param port: scanned port
        :return: tuple of dict of portocols and  dict of problems
        '''
        results = {}
        problems = {}
        if node:
            for protocol in node.findall('table'):
                key = '%s:%s-%s' % (host, port, protocol.attrib['key'])
                ciphers = []
                for cipher in protocol.findall("table[@key='ciphers']/table"):
                    name = cipher.find("elem[@key='name']").text
                    strength = cipher.find("elem[@key='strength']").text

                    ciphers.append('%s - %s' % (name, strength))

                warnings = []
                for warning in protocol.findall("table[@key='warnings']/elem"):
                    warnings.append(warning.text)

                results[key] = {
                    'host': host,
                    'port': port,
                    'name': key,
                    'protocol': protocol.attrib['key'],
                    'ciphers': '\r\n'.join(ciphers),
                    'warnings': '\r\n'.join(warnings),
                    'least_strength': node.find(
                        "elem[@key='least strength']").text
                }

                if warnings:
                    for warning in warnings:
                        warning_key = host + '-' + warning.replace(' ', '_')
                        if warning_key not in problems:
                            problems[warning_key] = {
                                'host': host,
                                'port': port,
                                'name': warning_key,
                                'warning': warning
                            }
        return results, problems

    @staticmethod
    def _parse_xml(data):
        root = ET.fromstring(data)
        runstats = root.find('runstats/finished')
        if runstats.attrib['exit'] != 'success':
            raise Exception(data)
        summary = runstats.attrib['summary']
        if '; 0 IP addresses' in summary:
            raise UnresolvableException(summary)

        # this is often unreliable
        # if '(0 hosts up)' in summary:
        #     raise UnreachableException(summary)
        return root

    @staticmethod
    def _cmd(params, timeout=200):
        """
        call of shell command
        :param params:
        :return:
        """
        return subprocess.check_output(params, timeout=timeout)

    @classmethod
    def parse(cls, string, ip4):
        '''
        parse namap output to statedata using xml
        :param string: xml output of nmap
        :return:  normalized data
        '''

        root = cls._parse_xml(string)
        state_data = {
            'ssl-services': {},
            'ssl-enum-ciphers': {},
            'ssl-problems': {}
        }

        for host in root.iter('host'):

            try:
                hostname = host.find(
                     # TODO shouldn't be @type='PTR' ??
                    "hostnames/hostname[@type='user']").attrib['name']
            except Exception:
                hostname = ip4

            for port in host.iter('port'):
                portid = port.attrib['portid']

                service_name = port.find('service').attrib.get('name')

                key = '%s:%s' % (hostname, portid)

                ssl_service = cls._parse_cert_info(port.find(
                    "script[@id='ssl-cert']"
                ))
                ssl_service['service'] = service_name
                ssl_enum_ciphers, ssl_problems = cls._parse_protocols(
                    port.find("script[@id='ssl-enum-ciphers']"),
                    hostname,
                    portid
                )
                ssl_service['protocols'] = []
                strengths = []

                for item in ssl_enum_ciphers.values():
                    ssl_service['protocols'].append(item.get('protocol'))
                    strengths.append(item.get('least_strength'))
                if not ssl_service['protocols']:
                    continue
                ssl_service['least_strength'] = min(strengths) if strengths \
                    else None

                ssl_service['protocols'] = ','.join(ssl_service['protocols'])
                ssl_service['name'] = key
                state_data['ssl-services'][key] = ssl_service
                state_data['ssl-enum-ciphers'] = ssl_enum_ciphers
                state_data['ssl-problems'] = ssl_problems

        return state_data

    @classmethod
    def run_check(cls, ip4, ports):
        params = ['nmap', '--script', '+ssl-cert,+ssl-enum-ciphers', '-oX',
                  '-', '-vv', '-p %s' % ','.join(map(str, ports)), ip4]
        err = ''
        state_data = {}
        try:
            data = cls._cmd(params)
            state_data = cls.parse(data, ip4)
            if not state_data['ssl-services']:
                raise Exception(
                    'Checked Ports: {}'.format(' '.join(map(str, ports))))


        except subprocess.CalledProcessError as e:
            err = 'Error: %s , %s' % (e.returncode, e.stderr)

        except ET.ParseError as e:
            err = 'Nmap output parsing error' % (e.msg)

        except FileNotFoundError:
            err = 'Nmap not installed in system'
        framework = {}
        framework['timestamp'] = int(time.time())
        return check_response(
            name=f'certificates {ip4} ({", ".join(map(str, ports))})',
            state_data=state_data,
            error=err,
            framework=framework
        )

    @classmethod
    async def get_data(cls, ip4, ports):
        if ports:
            data = None
            try:
                # TODO needs a asyncio.gather or asyncio wait to have any
                # effect
                async with SEMAPHORE:
                    data = cls.run_check(ip4, ports)
                print("DATA", data)
            except Exception:
                logging.exception('NMAP error\n')
                raise

            try:
                state = cls.get_result(data)
            except Exception:
                logging.exception('NMAP parse error\n')
                raise

            return state
        else:
            raise Exception(
                'CheckCertificates did not run; no ports are provided')
