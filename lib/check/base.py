import asyncio
import logging
import os
from agentcoreclient import IgnoreResultException

from .ports import DEFAULT_SSL_PORTS

DEFAULT_MAX_WORKERS = (os.cpu_count() or 1) * 5
SEMAPHORE = asyncio.Semaphore(value=DEFAULT_MAX_WORKERS)


class Base:
    type_name = None
    # interval is required, as it is used by agentcoreclient
    interval = 3600 * 4
    required = False

    @classmethod
    async def run(cls, data, asset_config=None):
        try:
            # If asset_id is needed in future; uncomment next line:
            # asset_id = data['hostUuid']
            config = data['hostConfig']['probeConfig']['wmiProbe']
            ip4 = config['ip4']
            check_certificate_ports = config.get(
                'checkCertificatePorts',
                DEFAULT_SSL_PORTS)
            check_ports = config.get('checkPorts', [])
            interval = data.get('checkConfig', {}).get('metaConfig', {}).get(
                'checkInterval')
            assert interval is None or isinstance(interval, int)
        except Exception:
            logging.error('invalid check configuration')
            return

        async with SEMAPHORE:
            max_runtime = 60  # 60 seconds
            try:
                state_data = await asyncio.wait_for(
                    cls.get_data(
                        ip4,
                        check_certificate_ports=check_certificate_ports,
                        check_ports=check_ports
                    ),
                    timeout=max_runtime
                )
            except IgnoreResultExceptionas as e:
                raise
            except asyncio.TimeoutError:
                raise Exception('Check timed out.')
            except Exception as e:
                raise Exception(f'Check error: {e.__class__.__name__}: {e}')
            else:
                return state_data

    @classmethod
    async def get_data(cls, *args, **kwargs):
        data = {}
        try:
            data = await cls.run_check(*args, **kwargs)
        except Exception as err:
            logging.exception(f'NMAP error: `{err}`\n')
            raise

        return data

    @staticmethod
    async def run_cmd(params):
        process = await asyncio.create_subprocess_exec(
            *params,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            raise Exception(
                (
                    f'Failed: {params}, pid={process.pid}, '
                    f'result: {stderr.decode().strip()}'
                ),
                flush=True,
            )

        return stdout

    @staticmethod
    async def run_check(*args, **kwargs):
        pass
