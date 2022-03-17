import argparse
import asyncio
import os
from agentcoreclient import AgentCoreClient
from setproctitle import setproctitle
from lib.check import CHECKS
from lib.version import __version__

# Migrate the nmap configuration and credentials
# TODO ????
def migrate_config_folder():
    if os.path.exists('/data/config/OsNmapProbe'):
        os.rename('/data/config/OsNmapProbe', '/data/config/nmapprobe')
    if os.path.exists('/data/config/nmapprobe/defaultCredentials.ini'):
        os.rename('/data/config/nmapprobe/defaultCredentials.ini',
                  '/data/config/nmapprobe/defaultAssetConfig.ini')

if __name__ == '__main__':
    setproctitle('nmapprobe')

    migrate_config_folder()  # TODO what todo?

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
