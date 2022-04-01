import logging
import subprocess
import xml.etree.ElementTree as ET

from .base import Base
from .exceptions import UnresolvableException
from .utils import get_ts_from_time_str, get_ts_utc_now


class CheckCertificates(Base):

    required = False
    interval = 3600 * 4

    @staticmethod
    def _parse_cert_info(node, host, port):
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

        not_before = get_ts_from_time_str(
            get_text('validity', 'notBefore')[:19])
        not_after = get_ts_from_time_str(
            get_text('validity', 'notAfter')[:19])
        now = get_ts_utc_now()

        is_valid = not_before <= now <= not_after
        expires_in = not_after - now

        response_data = {}
        name = f'{host}:{port}'
        response_data[name] = {
            'name': name,
            'subject': '/'.join(map(
                lambda elem: f'{elem.attrib["key"]}={elem.text}',
                node.findall("table[@key='subject']/elem")
            )),
            'issuer': '/'.join(map(
                lambda elem: f'{elem.attrib["key"]}={elem.text}',
                node.findall("table[@key='issuer']/elem")
            )),
            'validNotBefore': not_before,
            'validNotAfter': not_after,
            'isValid': is_valid,
            'expiresIn': expires_in,
            'pubkeyType': get_text('pubkey', 'type'),
            'pubkeyBits': get_text('pubkey', 'bits'),
            'md5': get_text('md5'),
            'sha1': get_text('sha1'),
        }
        return response_data

    @staticmethod
    def _parse_ciphers_info(node, host, port):
        response_data = {}
        if node:
            for protocol in node.findall('table'):
                ciphers = []
                for cipher in protocol.findall("table[@key='ciphers']/table"):
                    name = cipher.find("elem[@key='name']").text
                    strength = cipher.find("elem[@key='strength']").text

                    ciphers.append(f'{name} - {strength}')

                warnings = []
                for warning in protocol.findall("table[@key='warnings']/elem"):
                    warnings.append(warning.text)

                name = f'{host}:{port}-{protocol.attrib["key"]}'
                response_data[name] = {
                    'name': f'{host}:{port}-{protocol.attrib["key"]}',
                    'ciphers': '\r\n'.join(ciphers),
                    'warnings': '\r\n'.join(warnings),
                    'leastStrength': node.find(
                        "elem[@key='least strength']").text
                }

        return response_data

    @staticmethod
    def _parse_xml(data):
        root = ET.fromstring(data)
        runstats = root.find('runstats/finished')
        if runstats.attrib['exit'] != 'success':
            raise Exception(data)
        summary = runstats.attrib['summary']
        if '; 0 IP addresses' in summary:
            raise UnresolvableException(summary)

        return root

    @classmethod
    def parse(cls, string, ip4):
        root = cls._parse_xml(string)
        ssl_cert = {}
        ssl_enum_ciphers = {}

        for host in root.iter('host'):
            try:
                hostname = host.find(
                    'hostnames/hostname').attrib['name']
            except Exception:
                hostname = ip4

            for port in host.iter('port'):
                portid = port.attrib['portid']

                cert = cls._parse_cert_info(
                    port.find("script[@id='ssl-cert']"),
                    hostname,
                    portid
                )
                enum_ciphers = cls._parse_ciphers_info(
                    port.find("script[@id='ssl-enum-ciphers']"),
                    hostname,
                    portid
                )

                ssl_cert = {**ssl_cert, **cert}
                ssl_enum_ciphers = {**ssl_enum_ciphers, **enum_ciphers}

        return {
            'sslCert': ssl_cert,
            'sslEnumCiphers': ssl_enum_ciphers,
        }

    @classmethod
    async def run_check(
        cls,
        ip4,
        check_certificate_ports=None,
        **_kwargs
    ):
        logging.debug(
            f'run certificate check: {ip4} ports: {check_certificate_ports}')
        if check_certificate_ports:
            params = [
                'nmap',
                '--script',
                '+ssl-cert,+ssl-enum-ciphers',
                '-oX',
                '-',
                f"-p {','.join(map(str, check_certificate_ports))}",
                ip4
            ]

            response_data = {}
            try:
                data = await cls.run_cmd(params)
                response_data = cls.parse(data, ip4)
                if not response_data['sslCert']:
                    raise Exception((
                        'Checked Ports: '
                        f"{' '.join(map(str, check_certificate_ports))}"

                    ))

            except subprocess.CalledProcessError as e:
                raise Exception(f'Error: {e.returncode} , {e.stderr}')

            except ET.ParseError as e:
                raise Exception(f'Nmap parse error: {e.msg}')

            except FileNotFoundError:
                raise Exception('Nmap not installed in system')

            return response_data
        else:
            raise IgnoreResultException(
                'CheckCertificates did not run; no ports are provided')
