#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""MAC layer: TX/RX datapath components and core."""

from .core import MACCore
from .crc import CRC32, CRC32Check, CRC32Inserter, CRC32Checker
from .preamble import PreambleInserter, PreambleChecker
from .padding import PaddingInserter, PaddingChecker
from .gap import Gap
from .last_be import TXLastBE, RXLastBE
from .converter import EthStreamConverter

__all__ = [
    "MACCore",
    "CRC32", "CRC32Check", "CRC32Inserter", "CRC32Checker",
    "PreambleInserter", "PreambleChecker",
    "PaddingInserter", "PaddingChecker",
    "Gap",
    "TXLastBE", "RXLastBE",
    "EthStreamConverter",
]
