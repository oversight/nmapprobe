import asyncio
import datetime
import logging
from collections import defaultdict
from .utils import format_list


class Base:
    interval = 300
    required = False

    @classmethod
    def run(cls, data, asset_config=None):
        ...

    @classmethod
    async def get_data(cls, conn, service):
        ...
