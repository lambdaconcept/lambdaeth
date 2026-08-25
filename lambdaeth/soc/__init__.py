#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""SoC integration helpers: UART-to-Wishbone bridge, CSR plumbing."""

from .uart_bridge import UARTWishboneBridge

__all__ = ["UARTWishboneBridge"]
