import logging
import subprocess
import xml.etree.ElementTree as ET
from agentcoreclient import IgnoreResultException

from .base import Base


class CheckPorts(Base):

    type_name = 'port'
    required = False
    interval = 300

    @staticmethod
    def parse(data):
        response_data = {}
        root = ET.fromstring(data)
        for host in root.findall('host'):
            for port in host.findall('ports/port'):
                protocol = port.attrib['protocol']
                portid = int(port.attrib['portid'])
                state = port.find('state')
                name = f'{protocol}:{portid}'

                response_data[name] = {
                    'name': name,  # (str)
                    'state': state.attrib['state'],  # (str)
                    'reason': state.attrib['reason'],  # (str)
                    'reasonTTL': int(state.attrib['reason_ttl'])  # (int)
                }

        return response_data

    @classmethod
    async def run_check(cls, ip4, check_ports=None, **_kwargs):
        logging.debug(f'run ports check: {ip4} ports: {check_ports}')
        if check_ports:
            params = [
                'nmap',
                # first timeout at a low value for a port ping
                # retry at most twice but with a max timeout of 750ms
                # nmap gradually ramps up the timeout to the max-rtt-timeout
                # value. The settings used to be T4
                '--max-rtt-timeout', '750ms',
                '--min-rtt-timeout', '50ms',
                '--initial-rtt-timeout', '80ms',
                '--host-timeout', '10s',
                '--max-retries', '2',
                '--max-scan-delay', '3ms',  # the delay between scan packets
                '--version-intensity', '5',
                # The lower-numbered probes are effective
                # against a wide variety of common services,
                # while the higher-numbered ones are rarely useful.
                # default = 7
                '-oX',
                '-',
                f"-p {','.join(map(str, check_ports))}",
                ip4
            ]
            response_data = {}
            try:
                data = await cls.run_cmd(params)
                response_data[cls.type_name] = cls.parse(data)

            except subprocess.CalledProcessError as e:
                raise Exception(f'Error: {e.returncode} , {e.stderr}')

            except ET.ParseError as e:
                raise Exception(f'Nmap output parsing error: {e.msg}')

            except FileNotFoundError:
                raise Exception('Nmap not installed in system')

            except Exception:
                raise

            return response_data
        else:
            raise IgnoreResultException(
                'CheckPorts did not run; no ports are provided')
