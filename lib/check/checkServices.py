import logging
import subprocess
import time
import xml.etree.ElementTree as ET

from .base import Base, SEMAPHORE
from .utils import check_response


class CheckServices(Base):

    interval = 3600 * 24  # TODO ???
    required = True
    type_name = 'services'

    @staticmethod
    def _cmd(params, timeout=400):
        print(' '.join(params))
        return subprocess.check_output(params, timeout=timeout)

    @staticmethod
    def get_params(*args):
        """
        -T<X> indicates the timing template. T4 is used most. I've switched to
              a custom setup for performance reasons
        -T4 does the equivalent of --max-rtt-timeout 1250ms
            --min-rtt-timeout 100ms --initial-rtt-timeout 500ms --max-retries 6
            and sets the maximum TCP scan delay to 10 milliseconds
        -T5 does the equivalent of --max-rtt-timeout 300ms
            --min-rtt-timeout 50ms --initial-rtt-timeout 250ms --max-retries 2
            --host-timeout 15m --script-timeout 10m
            as well as setting the maximum TCP scan delay to 5ms

        :param args:
        :param kwargs:
        :return:
        """
        para = [
            "nmap",
            "-v",
            "-A",
            # first timeout at a low value for a port ping
            # retry at most twice but with a max timeout of 750ms
            # nmap gradually ramps up the timeout to the max-rtt-timeout value
            # The settings used to be T4
            "--max-rtt-timeout", "750ms",
            "--min-rtt-timeout", "50ms",
            "--initial-rtt-timeout", "80ms",
            "--script-timeout", "400s",
            "--host-timeout", "400s",
            "--max-retries", "2",
            "--max-scan-delay", "3ms",  # the delay between scan packets
            "--version-intensity", "5",  # -A does a version scan like -sV
            # The lower-numbered probes are effective
            # against a wide variety of common services,
            # while the higher-numbered ones are rarely useful.
            # default = 7
            "-F",
            "-oX",
            "-"]
        para += args
        print(para, args)
        return para

    @staticmethod
    def parse(data, ip4):
        result = {}
        root = ET.fromstring(data)
        # found_ports = []
        for host in root.findall("host"):

            try:
                hostname = host.find("hostnames/hostname[@type='user']").attrib['name']
            except Exception:
                hostname = ip4

            for port in host.findall("ports/port"):
                port_id = int(port.attrib['portid'])
                service = port.find("service")
                name = f"{hostname}:{port_id}"
                service_name = " - ".join(filter(bool, (service.attrib.get("name"),
                                                        service.attrib.get("product"),
                                                        service.attrib.get('extrainfo'))))

                # found_ports.append({
                #     'port': port_id,
                #     'description': service_name
                # })
                result[name] = {
                    "name": name,
                    "port": port_id,
                    "service": service_name}

        # TODO why is this done?
        # self.setInHostCacheFile('found_ports', found_ports)
        return result

    @classmethod
    def run_check(cls, ip4):
        """
        Chceck impl
        :param args:
        :param kwargs:
        :return:
        """
        err = ''
        state_data = {}
        try:
            data = cls._cmd(cls.get_params(ip4))
            state_data = {cls.type_name: cls.parse(data, ip4)}

        except subprocess.CalledProcessError as e:
            err = "Error: %s , %s" % (e.returncode, e.stderr)

        except ET.ParseError as e:
            err = "Nmap output parsing error" % e.msg

        except FileNotFoundError:
            err = "Nmap not installed in system"

        except Exception as e:
            err = str(e)  # TODO ??

        framework = {}
        framework['timestamp'] = int(time.time())
        return check_response(
            name=f'services {ip4}',
            state_data=state_data,
            error=err,
            framework=framework
        )


    @staticmethod
    def on_item(itm):
        return {
            'name': itm.name,  # (str)
        }

    @classmethod
    async def get_data(cls, ip4):
        data = None
        try:
            async with SEMAPHORE:
                data = cls.run_check(ip4)
            print('DATA',data)
        except Exception:
            logging.exception('NMAP error\n')
            raise

        try:
            state = cls.get_result(data)
        except Exception:
            logging.exception('NMAP parse error\n')
            raise

        return state
