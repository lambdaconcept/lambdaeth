#
# This file is part of LambdaEth, an Amaranth HDL port of LiteEth.
#
# SPDX-License-Identifier: BSD-2-Clause

"""Simulation helpers for eth_phy streams (struct payloads with data/last_be/error)."""

import random
import zlib


def crc32_bytes(data):
    """FCS of ``data`` as 4 bytes in wire order."""
    return list(zlib.crc32(bytes(data)).to_bytes(4, "little"))


def packet_to_beats(data, data_width=8, *, with_last_be=True, error=0):
    """Convert a list of bytes into a list of beat dicts for an eth_phy stream.

    When ``with_last_be`` is False (8-bit producers), only ``last`` is driven.
    """
    nbytes = data_width // 8
    assert len(data) > 0
    beats = []
    for off in range(0, len(data), nbytes):
        chunk = data[off:off + nbytes]
        word = 0
        for i, byte in enumerate(chunk):
            word |= byte << (8*i)
        last = off + nbytes >= len(data)
        beat = {
            "data":    word,
            "first":   off == 0,
            "last":    last,
            "last_be": (1 << (len(chunk) - 1)) if (last and with_last_be) else 0,
            "error":   error,
        }
        beats.append(beat)
    return beats


def beats_to_packet(beats, data_width=8):
    """Convert received beat dicts back into a list of bytes (trims on last_be)."""
    nbytes = data_width // 8
    data = []
    for beat in beats:
        nvalid = nbytes
        if beat["last"]:
            last_be = beat["last_be"]
            if last_be != 0:
                assert last_be.bit_count() == 1, f"last_be not one-hot: {last_be:#x}"
                nvalid = last_be.bit_length()
        for i in range(nvalid):
            data.append((beat["data"] >> (8*i)) & 0xff)
    return data


async def send_beats(ctx, ep, beats, *, domain="sync", stall_rate=0.0, rng=None):
    """Drive ``beats`` into stream ``ep``, one handshake per beat."""
    rng = rng or random.Random(0)
    for beat in beats:
        while stall_rate and rng.random() < stall_rate:
            ctx.set(ep.valid, 0)
            await ctx.tick(domain=domain)
        ctx.set(ep.valid, 1)
        ctx.set(ep.p.data, beat["data"])
        ctx.set(ep.p.last_be, beat.get("last_be", 0))
        ctx.set(ep.p.error, beat.get("error", 0))
        ctx.set(ep.first, beat.get("first", 0))
        ctx.set(ep.last, beat.get("last", 0))
        await ctx.tick(domain=domain).until(ep.ready)
        ctx.set(ep.valid, 0)
    ctx.set(ep.last, 0)
    ctx.set(ep.first, 0)


async def recv_beats(ctx, ep, *, domain="sync", stall_rate=0.0, rng=None,
                     timeout=100_000):
    """Consume one packet (until ``last``) from stream ``ep``; returns beat dicts."""
    rng = rng or random.Random(1)
    beats = []
    for _ in range(timeout):
        ready = 0 if (stall_rate and rng.random() < stall_rate) else 1
        ctx.set(ep.ready, ready)
        _clk, _rst, valid, data, last_be, error, first, last = \
            await ctx.tick(domain=domain) \
                .sample(ep.valid, ep.p.data, ep.p.last_be, ep.p.error, ep.first, ep.last)
        if ready and valid:
            beats.append({
                "data":    data,
                "last_be": last_be,
                "error":   error,
                "first":   first,
                "last":    last,
            })
            if last:
                ctx.set(ep.ready, 0)
                return beats
    raise TimeoutError("no complete packet received")


async def send_packet(ctx, ep, data, data_width=8, **kwargs):
    await send_beats(ctx, ep, packet_to_beats(data, data_width,
                     with_last_be=kwargs.pop("with_last_be", True)), **kwargs)


async def recv_packet(ctx, ep, data_width=8, **kwargs):
    beats = await recv_beats(ctx, ep, **kwargs)
    return beats_to_packet(beats, data_width), beats
