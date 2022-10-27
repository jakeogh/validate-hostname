#!/usr/bin/env python3

import re

import click
# from asserttool import ic
from clicktool import click_add_options
from clicktool import click_global_options

# from eprint import eprint
from validate_hostname_test_vectors import get_test_vectors


class HostnameValidator:
    def __init__(self):
        # permits all numeric tld's, accepts invalid ips, accepts "..", but gets everything(?) else right. From freenode@#postgresql:RhodiumToad
        # self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"

        # prevent ".."
        # self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"

        # prevent ".." and allow trailing .
        self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"  # prevent ".." and allow trailing .

        # IP validation, fails on 127.1 http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
        self.ip_constraint_regex = "^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"
        self.constraint_regex = (
            self.hostname_constraint_regex + "|" + self.ip_constraint_regex
        )

    def get_sqlalchemy_constraint(self):
        self.hostname_constraint = "name ~ '" + self.hostname_constraint_regex + "'"
        self.ip_constraint = "name ~ '" + self.ip_constraint_regex + "'"
        self.constraint = "name ~ '" + self.constraint_regex + "'"
        return self.constraint

    def get_compiled_regex(self):
        regex = re.compile(self.constraint_regex)
        return regex


def test_hostname(regex, name):
    answer = regex.fullmatch(name)
    if answer == None:
        raise AssertionError
    return True


@click.command()
@click.option("--ipython", is_flag=True)
@click_add_options(click_global_options)
@click.pass_context
def cli(
    ctx,
    *,
    verbose: bool | int | float,
    verbose_inf: bool,
    dict_output: bool,
    ipython: bool,
):

    """
    RFC 952: https://tools.ietf.org/html/rfc952

    1. A "name" (Net, Host, Gateway, or Domain name) is a text string up
    to 24 characters drawn from the alphabet (A-Z), digits (0-9), minus
    sign (-), and period (.).  Note that periods are only allowed when
    they serve to delimit components of "domain style names". (See
    RFC-921, "Domain Name System Implementation Schedule", for
    background).  No blank or space characters are permitted as part of a
    name. No distinction is made between upper and lower case.  The first
    character must be an alpha character.  The last character must not be
    a minus sign or period.

    RFC 1123: https://tools.ietf.org/html/rfc1123#page-13

    The syntax of a legal Internet host name was specified in RFC-952
    [DNS:4].  One aspect of host name syntax is hereby changed: the
    restriction on the first character is relaxed to allow either a
    letter or a digit.  Host software MUST support this more liberal
    syntax.

    Host software MUST handle host names of up to 63 characters and
    SHOULD handle host names of up to 255 characters.

    Whenever a user inputs the identity of an Internet host, it SHOULD
    be possible to enter either (1) a host domain name or (2) an IP
    address in dotted-decimal ("#.#.#.#") form.  The host SHOULD check
    the string syntactically for a dotted-decimal number before
    looking it up in the Domain Name System.
    """

    validator = HostnameValidator()
    regex = validator.get_compiled_regex()
    test_vectors = get_test_vectors()

    for item in test_vectors:
        try:
            test_hostname(regex, item[0])
        except AssertionError:
            if item[1] == True:  # if the test is supposed to work
                print(
                    "test: (FAIL) ----ERROR----",
                    item,
                    "was expected to work, but did not.",
                )
            else:
                print("test: (PASS)", item)
                pass  # test was supposed to fail, and it did
        else:
            if item[1] == False:  # if a test that was supposed to fail didnt
                print(
                    "test: (FAIL) ----ERROR----",
                    item,
                    "was expected to fail, but did not.",
                )
            else:
                print("test: (PASS)", item)


if __name__ == "__main__":
    # pylint: disable=E1120
    # pylint: disable=E1125
    cli()
