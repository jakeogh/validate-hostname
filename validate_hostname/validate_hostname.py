#!/usr/bin/env python3
# -*- coding: utf8 -*-

# pylint: disable=missing-docstring               # [C0111] docstrings are always outdated and wrong
# pylint: disable=fixme                           # [W0511] todo is encouraged
# pylint: disable=line-too-long                   # [C0301]
# pylint: disable=too-many-instance-attributes    # [R0902]
# pylint: disable=too-many-lines                  # [C0302] too many lines in module
# pylint: disable=invalid-name                    # [C0103] single letter var names, name too descriptive
# pylint: disable=too-many-return-statements      # [R0911]
# pylint: disable=too-many-branches               # [R0912]
# pylint: disable=too-many-statements             # [R0915]
# pylint: disable=too-many-arguments              # [R0913]
# pylint: disable=too-many-nested-blocks          # [R1702]
# pylint: disable=too-many-locals                 # [R0914]
# pylint: disable=too-few-public-methods          # [R0903]
# pylint: disable=no-member                       # [E1101] no member for base
# pylint: disable=attribute-defined-outside-init  # [W0201]
# pylint: disable=too-many-boolean-expressions    # [R0916] in if statement
from __future__ import annotations

from signal import SIG_DFL
from signal import SIGPIPE
from signal import signal

import click

signal(SIGPIPE, SIG_DFL)
from collections.abc import Sequence

from asserttool import ic
from clicktool import click_add_options
from clicktool import click_global_options


@click.command()
@click.argument("hostnames", type=str, nargs=-1)
@click.option("--verbose", is_flag=True)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    hostnames: Sequence[str],
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_input: bool,
):

    iterator = hostnames

    index = 0
    for index, hostname in enumerate(iterator):
        if verbose:
            ic(index, hostname)
