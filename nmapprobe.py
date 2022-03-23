import argparse
import asyncio

from agentcoreclient import AgentCoreClient
from setproctitle import setproctitle
from lib.check import CHECKS
from lib.version import __version__


if __name__ == '__main__':
    setproctitle('nmapprobe')

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-l', '--log-level',
        default='warning',
        help='set the log level',
        choices=['debug', 'info', 'warning', 'error'])

    parser.add_argument(
        '--log-colorized',
        action='store_true',
        help='use colorized logging')

    args = parser.parse_args()

    cl = AgentCoreClient(
        'nmapProbe',
        __version__,
        CHECKS,
        None,
        '/data/config/nmapprobe/nmapProbe-config.json'
    )

    cl.setup_logger(args.log_level, args.log_colorized)

    asyncio.get_event_loop().run_until_complete(
        cl.connect_loop()
    )
