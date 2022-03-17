import asyncio
import logging
import os

DEFAULT_MAX_WORKERS = (os.cpu_count() or 1) * 5
SEMAPHORE = asyncio.Semaphore(value=DEFAULT_MAX_WORKERS)


class Base:
    type_name = None
    interval = 300  # interval is required, as it is used by agentcoreclient
    required = False

    @classmethod
    async def run(cls, data, asset_config=None):
        try:
            # If asset_id is needed in future; uncomment next line:
            # asset_id = data['hostUuid']
            config = data['hostConfig']['probeConfig']['wmiProbe']
            ip4 = config['ip4']
            ports = config.get('checkCertificatePorts', None)
            interval = data.get('checkConfig', {}).get('metaConfig', {}).get(
                'checkInterval')
            assert interval is None or isinstance(interval, int)
        except Exception:
            logging.error('invalid check configuration')
            return

        max_runtime = .8 * (interval or cls.interval)  # TODO ?
        try:
            state_data = await asyncio.wait_for(
                cls.get_data(ip4, ports),
                timeout=max_runtime
            )
        except asyncio.TimeoutError:
            raise Exception('Check timed out.')
        except Exception as e:
            raise Exception(f'Check error: {e.__class__.__name__}: {e}')
        else:
            return state_data

    @classmethod
    async def get_data(cls, ip4, ports):
        pass

    @staticmethod
    async def run_check(ip4, ports):
        pass

    @staticmethod
    def on_item(itm):
        return itm

    @classmethod
    def get_result(cls, data):
        itm = cls.on_item(data)
        state = {}
        state[cls.type_name] = {}
        name = itm['name']
        state[cls.type_name][name] = itm
        return state

