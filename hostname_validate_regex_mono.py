#!/usr/bin/env python3
# https://github.com/jakeogh/domainname-validate
import re
import pprint
import shutil
from collections import defaultdict

def pprint_color(obj):
    print(highlight(pformat(obj), PythonLexer(), Terminal256Formatter()))

class HostnameValidator():
    def __init__(self):
        self.regex_names = ['domainname', 'hostname', 'label', 'ipv4', 'ipv6', 'all']
        #self.domainname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                              # permits all numeric tld's, accepts invalid ips, accepts "..", but gets everything(?) else right. From freenode@#postgresql:RhodiumToad
        #self.domainname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                  # prevent ".."
        #self.domainname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"  # prevent ".." and allow trailing .
        #self.domainname_constraint_regex = r"""(?=^.{1,63}$)^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$""" # limit len to 63  From freenode@#python:bok^3
        self.domainname_constraint_regex = r"""
                                            (?=^.{1,255}$)                                          # limit total hostname length to 255
                                            ^(?!.*-$)                                               # trailing - are not valid
                                            ^(?!.*\.[0-9]*$)                                        # trailing 0-9 are not valid, there are no all numeric TLD's and if there were it would break things
                                            (?!.*-[.])                                              # no - before a .
                                            (?!.*[.][.])                                            # no repeating .
                                            (?:[A-Za-z0-9][A-Za-z0-9-]*)
                                            (?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"""

        '''
        RFC952 + RFC1123 on host names:
        1. A "name" (Net, Host, Gateway, or Domain name) is a:
            text string up to 255 characters drawn from the alphabet:
                [A-Za-z]
                digits [0-9]
                minus sign [-]

        No blank or space characters are permitted.
        No distinction is made between upper and lower case.
        The first character must be an letter or digit.
        The last character must not be a minus sign or period.
        Single character names or nicknames are not allowed.
        '''

        # http://stackoverflow.com/questions/2063213/regular-expression-for-validating-dns-label-host-name
        #self.hostname_constraint_regex = r"""^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$"""
        #self.hostname_constraint_regex = r"""^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,255}(?<!-)$""" # accept up to 255 bytes
        self.hostname_constraint_regex = r"""^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,255}(?<!-)$""" # do not accept empty labels

        # http://stackoverflow.com/questions/2063213/regular-expression-for-validating-dns-label-host-name
        #self.label_constraint_regex = r"""^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$"""
        self.label_constraint_regex = r"""^(?!-)[a-zA-Z0-9-]{1,255}(?<!-)$""" # accept up to 255 bytes


        # http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
        #self.ipv4_constraint_regex = r"""^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"""
        #self.ipv4_constraint_regex = r"""(?=^.{1,14}$)^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"""
        self.ipv4_constraint_regex = r"""
                                        (?=^.{1,14}$)                           # max ipv4 length 3*4+3*1 = 15
                                        ^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}
                                        ([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"""

        # http://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
        #self.ipv4_constraint_regex = r"""^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""" # matches invalid ipv4 00.00.00.00 (leading 0's mean octal)
        self.ipv4_constraint_regex = r"""
                                        ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}
                                        (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$""" # matches invalid ipv4 00.00.00.00 (leading 0's mean octal by convention and should not be considered valid ipv4)


        # https://gist.github.com/syzdek/6086792
        IPV6SEG  = """[0-9a-fA-F]{1,4}"""
        self.ipv6_constraint_regex = r"""(
                                        (%s:){7,7}%s|                                      # 1:2:3:4:5:6:7:8
                                        (%s:){1,7}:|                                       # 1::                              1:2:3:4:5:6:7::
                                        (%s:){1,6}:%s|                                     # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
                                        (%s:){1,5}(:%s){1,2}|                              # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
                                        (%s:){1,4}(:%s){1,3}|                              # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
                                        (%s:){1,3}(:%s){1,4}|                              # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
                                        (%s:){1,2}(:%s){1,5}|                              # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
                                        %s:((:%s){1,6})|                                   # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
                                        :((:%s){1,7}|:)|                                   # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::

                                        fe80:(:[0-9a-fA-F]{0,4}){0,4}%%[0-9a-zA-Z]{1,}|    # fe80::7:8%%eth0  fe80::7:8%%1    (link-local IPv6 addresses with zone index)

                                        ::(ffff(:0{1,4}){0,1}:){0,1}
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)

                                        (%s:){1,5}:
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
                                        )"""


        IPV6SEG  = """[0-9a-fA-F]{1,4}"""
        self.ipv6_constraint_regex = r"""(
                                        (%s:){7,7}%s|                                      # 1:2:3:4:5:6:7:8
                                        (%s:){1,7}:|                                       # 1::                              1:2:3:4:5:6:7::
                                        (%s:){1,6}:%s|                                     # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
                                        (%s:){1,5}(:%s){1,2}|                              # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
                                        (%s:){1,4}(:%s){1,3}|                              # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
                                        (%s:){1,3}(:%s){1,4}|                              # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
                                        (%s:){1,2}(:%s){1,5}|                              # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
                                        %s:((:%s){1,6})|                                   # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
                                        :((:%s){1,7}|:)|                                   # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::

                                        fe80:(:[0-9a-fA-F]{0,4}){0,4}%%[0-9a-zA-Z]{1,}|    # fe80::7:8%%eth0  fe80::7:8%%1    (link-local IPv6 addresses with zone index)

                                        ::(ffff(:0{1,4}){0,1}:){0,1}
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)


                                        ((((%s:){1,6})(:){0,1})
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))          # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
                                        )"""

        #self.ipv6_constraint_regex_temp = r"""(([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"""
        #self.ipv6_constraint_regex_temp = r"""(([0-9a-fA-F]{1,4}:){1,5}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"""
        #self.ipv6_constraint_regex_temp = r"""((([0-9a-fA-F]{1,4}:){1,5}):((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"""
        self.ipv6_constraint_regex_temp = r"""(((([0-9a-fA-F]{1,4}:){1,6})(:){0,1})((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))""" # first attempt to fix 2001:db8::3:4:192.0.2.33, not there yet

        self.ipv6_constraint_regex = self.ipv6_constraint_regex % (17*(IPV6SEG,))

        # http://home.deds.nl/~aeron/regex/
        #self.ipv6_constraint_regex = r"""^(((?=.*(::))(?!.*\3.+\3))\3?|[\dA-F]{1,4}:)([\dA-F]{1,4}(\3|:\b)|\2){5}(([\dA-F]{1,4}(\3|:\b|$)|\2){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})\Z"""

        self.all_constraint_regex = self.domainname_constraint_regex + '|' + self.ipv4_constraint_regex + '|' + self.ipv6_constraint_regex
        self.ip_constraint_regex = self.ipv4_constraint_regex + '|' + self.ipv6_constraint_regex
        self.regex_dict = {}

    def get_sqlalchemy_constraint(self):
        self.name_constraint = "name ~ \'" + self.name_constraint_regex + "\'"
        self.ip_constraint = "name ~ \'" + self.ipv4_constraint_regex + "\'"
        self.constraint = "name ~ \'" + self.constraint_regex + "\'"
        return self.constraint

    def get_compiled_regex(self):
        regex = re.compile(self.all_constraint_regex, re.VERBOSE)
        return regex

    def get_compiled_regex_dict(self):
        #regex_dict = re.compile(self.all_constraint_regex, re.VERBOSE)
        for name in self.regex_names:
            #regex_to_compile = getattr(self, "self." + name + "_constraint_regex")
            regex_to_compile = getattr(self, name + "_constraint_regex")
            self.regex_dict[name] = re.compile(regex_to_compile, re.VERBOSE)
        return self.regex_dict

    def test_thing(self, regex, name):
        answer = regex.fullmatch(name)
        if answer == None:
            raise AssertionError
        return True

def get_test_vectors():
    test_vectors = []

    # valid hostnames that only match the hostnamename regex:
    test_vectors.append(('net',                                           {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard domain"))

    # valid hostnames that match the hostnamename regex and the domainname regex:
    test_vectors.append(('net',                                           {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('NET',                                           {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('N-E-T',                                         {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('N-E-T',                                         {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('3N-E-T',                                        {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('3n-e-t',                                        {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append(('n-e-t3',                                        {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname"))
    test_vectors.append((255*'a',                                         {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, "standard hostname max length 255 bytes"))

    # invalid hostnames that match no regex:
    test_vectors.append(('-net',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid leading -"))
    test_vectors.append(('n_et',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid _"))
    test_vectors.append(('net-',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid trailing -"))
    test_vectors.append(('net--',                                         {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid trailing -"))
    test_vectors.append(('net.',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid trailing ."))
    test_vectors.append(('.net',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "hostname with invalid leading ."))
    test_vectors.append((256*'A',                                         {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid hostname > 255 bytes"))


    # valid domainnames that only match the domainname regex:
    test_vectors.append(('lwn.net',                                       {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard domain"))
    test_vectors.append(('net',                                           {'domainname':True, 'hostname':True, 'label':True,  'ipv4':False, 'ipv6':False}, "standard domain without a ."))
    test_vectors.append(('3.net',                                         {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard domain starting with a number"))
    test_vectors.append(('LWN.NET',                                       {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard domain uppercase"))
    test_vectors.append(('l-w-n.n-e-t',                                   {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes"))
    test_vectors.append(('l-w-n.XN--1QQW23A',                             {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes"))
    test_vectors.append(('l'*59+'.net',                                   {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid (63 max) name length")) # 59 + 4 = 63
    test_vectors.append(('l'*251+'.net',                                  {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid 255 max length name")) # 251 + 4 = 255
    # http://archive.oreilly.com/pub/post/the_worlds_longest_domain_name.html
    test_vectors.append(('www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com', {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid real world 71 char name"))
    test_vectors.append(('3.141592653589793238462643383279502884197169399375105820974944592.com',   {'domainname':True, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid real world 69 char name with all numbers except for the TLD"))

    # invalid domainnames that are correctly not matched by any regex:
    test_vectors.append(('lwn.net.',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard domain with invalid trailing dot")) #RFC952 implies this should not be valid...
    test_vectors.append(('l-w-n.XN--1QQW23A.',                            {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes with invalid trailing dot"))
    test_vectors.append(('l-w-n.n-e-t.',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes with invalid trailing dot"))
    test_vectors.append(('l wn.net',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid space"))
    test_vectors.append(('l	wn.net',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid tab"))
    test_vectors.append(('.lwn.net',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid leading dot"))
    test_vectors.append(('lwn..net',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid double dots"))
    test_vectors.append(('.lwn.net.',                                     {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain invalid trailing dot with invalid leading dot"))
    test_vectors.append(('-lwn.net',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid leading dash"))
    test_vectors.append(('lwn-.net',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid dash before a dot"))
    test_vectors.append(('l-w-n.XN--1QQW23A-',                            {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "use of dashes with invalid trailing dash"))
    test_vectors.append(('l'*252+'.net',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid >255 max length name")) # 252 + 4 = 256
    test_vectors.append(('☃.net',                                         {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid UTF8 char in domainname"))
    test_vectors.append(('lwn.111',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid all numeric TLD")) #otherwise it's not possible to distinguish 127.111.111.1111 from a domain
    test_vectors.append(('fcon_1000.pro.test.org',                        {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard domain with valid underscore")) # http://stackoverflow.com/questions/2180465/can-domain-name-subdomains-have-an-underscore-in-it

    # valid ipv4 that only match the ipv4 regex:
    test_vectors.append(('0.0.0.0',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('1.1.1.1',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('2.2.2.2',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('3.3.3.3',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('4.4.4.4',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('5.5.5.5',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('0.0.0.1',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('0.0.1.2',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('0.1.2.3',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('1.2.3.4',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('2.3.4.5',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('3.4.5.0',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('4.5.0.1',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('5.0.1.2',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('1.2.3.4',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(('127.0.0.1',                                     {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, "valid use of ip"))
    test_vectors.append(('55.55.55.55',                                   {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))

    # valid ipv4 that is incorrectly not matched by the ipv4 regex
    test_vectors.append(('255.255.255.255',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))

    # valid ipv6 that only match the ipv6 regex:
    test_vectors.append(('0:0:0:0:0:0:0:1',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 loopback"))
    test_vectors.append(('::1',                                           {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 loopback abbreviated"))
    test_vectors.append(('::',                                            {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 0:0:0:0:0:0:0:0"))
    test_vectors.append(('2001:4860:4860::8888',                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 version of 8.8.8.8"))
    test_vectors.append(('2001:0000:0234:C1AB:0000:00A0:AABC:003F',       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 standard address")) # http://www.zytrax.com/tech/protocols/ipv6.html
    test_vectors.append(('2001::0234:C1ab:0:A0:aabc:003F',                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 standard address with single 0 dropped"))
    test_vectors.append(('2001:db8:3:4::192.0.2.33',                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address")) # https://gist.github.com/syzdek/6086792
    test_vectors.append(('1:2:3:4:5:6:7:8',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::',                                           {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::8',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::7:8',                                        {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::6:7:8',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::5:6:7:8',                                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::4:5:6:7:8',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::3:4:5:6:7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('::2:3:4:5:6:7:8',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('fe80::7:8%eth0',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 link-local IPv6 addresses with zone index"))
    test_vectors.append(('fe80::7:8%1',                                   {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 link-local IPv6 addresses with zone index"))
    test_vectors.append(('::255.255.255.255',                             {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('::ffff:255.255.255.255',                        {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('::ffff:0:255.255.255.255',                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4:5:6::8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4:5::7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4::6:7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3::5:6:7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2::4:5:6:7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::3:4:5:6:7:8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('::2:3:4:5:6:7:8',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4:5:6:7::',                               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4:5:6::8',                                {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4:5::8',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3:4::8',                                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2:3::8',                                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1:2::8',                                        {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('1::8',                                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('::8',                                           {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6"))
    test_vectors.append(('2001:db8:3:4::192.0.2.33',                      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 IPv4-Embedded IPv6 Address"))
    test_vectors.append(('64:ff9b::192.0.2.33',                           {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 IPv4-Embedded IPv6 Address"))
    test_vectors.append(('ABCD:ABCD:ABCD:ABCD::192.168.158.190',          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address less than max length"))

    # valid ipv6 that are incorrectly not matched by the ipv6 regex
    test_vectors.append(('2001:db8::FFFF:192.168.0.1',                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address")) # https://gist.github.com/syzdek/6086792
    test_vectors.append(('ABCD:ABCD:ABCD:ABCD:ABCD:ABCD:192.168.158.190', {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address max length"))
    test_vectors.append(('ABCD:ABCD:ABCD:ABCD:ABCD::192.168.158.190',     {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address less than max length"))

    # invalid ipv4 that are correctly not matched by any regex:
    # ipv4 has no RFC spec to drop octets, it's a mess: http://superuser.com/questions/486788/why-does-pinging-192-168-072-only-2-dots-return-a-response-from-192-168-0-58
    test_vectors.append(('127.1',                                         {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of implied octet"))        # most web browsers are ok with missing octets
    test_vectors.append(('127.0.1',                                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "valid use of implied octet"))        # but this validation regex is not
    test_vectors.append(('127.0.0.1.',                                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ipv4 with invalid trailing dot"))
    test_vectors.append(('127.000.0.1.',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid use of ip with leading 0s and invalid trailing dot"))
    test_vectors.append(('127.000.0.1',                                   {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invalid valid use of ip with leading 0s"))
    test_vectors.append(('1.1.1.1:25',                                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "the port is not a part of an ipv4 address"))
    test_vectors.append(('127.0.800',                                     {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "only ipv4 dotted decimal format is accepted, this would convert to 127.0.3.32 if interperted as octal"))
    test_vectors.append(('757161601',                                     {'domainname':False, 'hostname':False, 'label':True, 'ipv4':False, 'ipv6':False}, "only ipv4 dotted decimal format is accepted, this would convert to 45.33.94.129 (is/was lwn.net) if interperted as a u32bit int")) #todo double check that all numeric names are ok RFC1123 says this is a valid "label" but not a valid hostname.

    # invalid ipv6 that are correctly not matched by any regex
    test_vectors.append(('2001:0000:0234:C1AB:0000:00A0:AABC::003F',      {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 standard address with invalid extra :")) # http://www.zytrax.com/tech/protocols/ipv6.html
    test_vectors.append(('2001::0234:C1ab::A0:aabc:003F',                 {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 one or more zeros entries can be omitted entirely but only once in an address"))
    test_vectors.append(('2404:6800::4003:c02::8a',                       {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 one or more zeros entries can be omitted entirely but only once in an address"))
    test_vectors.append(('2001:db8:0:::0:FFFF:192.168.0.5',               {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "invlaid IPV6 hybrid address with two 0's dropped"))
    test_vectors.append(('2001:db8:0::0:0:FFFF:192.168.0.5',              {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 hybrid address with single 0 dropped and invalid 7 16bit valies before the ipv4 instead of 6"))
    test_vectors.append(('2001:db8:0:0:0:0:FFFF:192.168.0.5',             {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 hybrid address with invalid 7 16bit valies before the ipv4 instead of 6")) # http://www.zytrax.com/tech/protocols/ipv6.html
    test_vectors.append((':: ',                                           {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 0:0:0:0:0:0:0:0 with invalid space at the end"))
    test_vectors.append(('0:	:0:0:0:0:0:1',                            {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "IPV6 loopback with invalid TAB in it"))

    # invalid ipv6 that are incorrectly matched by ipv6 (or any) regex:
    test_vectors.append(('6666:123.123.123.123',                          {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))

    # invalid ipv4 that are correctly not matched by any regex:
    test_vectors.append(('127.0000.0.1',                                  {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "too many leading 0s"))
    test_vectors.append(('0127.0.0.1',                                    {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "too many leading 0s"))
    test_vectors.append(('127.0.0.0.1',                                   {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "too many octs"))
    test_vectors.append(('127.111.111.1111',                              {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ipv4 too long"))
    test_vectors.append(('527.0.0.1',                                     {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ipv4 out of range >255.255.255.255"))
    test_vectors.append(('00.00.00.00',                                   {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ipv4 out of range >255.255.255.255"))
    test_vectors.append(('3...3',                                         {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ipv4 multiple ."))



    #http://www.helpsystems.com/intermapper/ipv6-test-address-validation

    # from http://download.dartware.com/thirdparty/test-ipv6-regex.pl
    # contains manual fixes
    test_vectors.append(("", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "empty string"))
    test_vectors.append(("::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "loopback, compressed, non-routable"))
    test_vectors.append(("::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "unspecified, compressed, non-routable"))
    test_vectors.append(("0:0:0:0:0:0:0:1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "loopback, full"))
    test_vectors.append(("0:0:0:0:0:0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "unspecified, full"))
    test_vectors.append(("2001:DB8:0:0:8:800:200C:417A", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "unicast, full"))
    test_vectors.append(("FF01:0:0:0:0:0:0:101", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "multicast, full"))
    test_vectors.append(("2001:DB8::8:800:200C:417A", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "unicast, compressed"))
    test_vectors.append(("FF01::101", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "multicast, compressed"))
    test_vectors.append(("2001:DB8:0:0:8:800:200C:417A:221", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "unicast, full"))
    test_vectors.append(("FF01::101::2", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "multicast, compressed"))
    test_vectors.append(("fe80::217:f2ff:fe07:ed62", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0000:1234:0000:0000:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("3ffe:0b00:0000:0000:0001:0000:0000:000a", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("FF02:0000:0000:0000:0000:0000:0000:0001", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0000:0000:0000:0000:0000:0000:0000:0001", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0000:0000:0000:0000:0000:0000:0000:0000", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("02001:0000:1234:0000:0000:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "extra 0 not allowed!"))
    test_vectors.append(("2001:0000:1234:0000:00001:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "extra 0 not allowed!"))
    test_vectors.append((" 2001:0000:1234:0000:0000:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "leading space")) #changed to ipv6:False
    test_vectors.append(("2001:0000:1234:0000:0000:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "trailing space"))
    test_vectors.append((" 2001:0000:1234:0000:0000:C1C0:ABCD:0876  ", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "leading and trailing space")) #changed to ipv6:False
    test_vectors.append(("2001:0000:1234:0000:0000:C1C0:ABCD:0876  0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "junk after valid address"))
    test_vectors.append(("2001:0000:1234: 0000:0000:C1C0:ABCD:0876", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "internal space"))
    test_vectors.append(("3ffe:0b00:0000:0001:0000:0000:000a", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "seven segments"))
    test_vectors.append(("FF02:0000:0000:0000:0000:0000:0000:0000:0001", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "nine segments"))
    test_vectors.append(("3ffe:b00::1::a", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "double ::"))
    test_vectors.append(("::1111:2222:3333:4444:5555:6666::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "double ::"))
    test_vectors.append(("2::10", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("ff02::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2002::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:db8::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:1234::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::ffff:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5:6:7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5:6::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::2:3:4:5:6:7", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::2:3:4:5:6", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::2:3:4:5", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::2:3:4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::2:3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3:4:5:6:7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3:4:5:6:7", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3:4:5:6", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3:4:5", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3:4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2:3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5:6::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::4:5::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "Double ::"))
    test_vectors.append(("12345::6:7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1:2:3:4::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::7:8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5:6:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4:5::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3:4::5:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2:3::5:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1:2::5:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::5:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::5:11.22.33.44", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1::5:400.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:260.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:256.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.256.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.256.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.3.256", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:300.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.300.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.300.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.3.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:900.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.900.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.900.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:1.2.3.900", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:300.300.300.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::5:3000.30.30.30", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::400.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::260.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::256.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.256.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.256.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.3.256", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::300.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.300.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.300.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.3.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::900.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.900.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.900.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::1.2.3.900", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::300.300.300.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::3000.30.30.30", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::400.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::260.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::256.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.256.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.256.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.3.256", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::300.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.300.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.300.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.3.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::900.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.900.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.900.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.3.900", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::300.300.300.300", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::3000.30.30.30", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("fe80::217:f2ff:254.7.237.98", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::ffff:192.168.1.26", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:1:1:1:1:1:255Z255X255Y255", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "garbage instead of . in IPv4"))
    test_vectors.append(("::ffff:192x168.1.26", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "ditto"))
    test_vectors.append(("::ffff:192.168.1.1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0:0:0:0:13.1.68.3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPv4-compatible IPv6 address, full, deprecated"))
    test_vectors.append(("0:0:0:0:0:FFFF:129.144.52.38", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPv4-mapped IPv6 address, full"))
    test_vectors.append(("::13.1.68.3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPv4-compatible IPv6 address, compressed, deprecated"))
    test_vectors.append(("::FFFF:129.144.52.38", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "IPv4-mapped IPv6 address, compressed"))
    test_vectors.append(("fe80:0:0:0:204:61ff:254.157.241.86", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::204:61ff:254.157.241.86", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::ffff:12.34.56.78", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::ffff:2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::ffff:257.1.2.3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4:1111:2222:3333:4444::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "Aeron"))
    test_vectors.append(("1.2.3.4:1111:2222:3333::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4:1111:2222::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4:1111::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("fe80:0000:0000:0000:0204:61ff:254.157.241.086", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::ffff:192.0.2.128", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "but this is OK, since there's a single digit"))
    test_vectors.append(("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:0.0.0.0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "https://tools.ietf.org/html/rfc5954#section-3.2"))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:00.00.00.00", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "https://tools.ietf.org/html/rfc5954#section-3.2"))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:000.000.000.000", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "https://tools.ietf.org/html/rfc5954#section-3.2"))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:256.256.256.256", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("2001:0DB8:0000:CD30:0000:0000:0000:0000/60", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "full, with prefix"))
    test_vectors.append(("2001:0DB8::CD30:0:0:0:0/60", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, with prefix"))
    test_vectors.append(("2001:0DB8:0:CD30::/60", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, with prefix 2"))
    test_vectors.append(("::/128", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, unspecified address type, non-routable"))
    test_vectors.append(("::1/128", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, loopback address type, non-routable"))
    test_vectors.append(("FF00::/8", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, multicast address type"))
    test_vectors.append(("FE80::/10", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, link-local unicast, non-routable"))
    test_vectors.append(("FEC0::/10", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "compressed, site-local unicast, deprecated"))
    test_vectors.append(("124.15.6.89/60", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, "standard IPv4, prefix not allowed"))
    test_vectors.append(("fe80:0000:0000:0000:0204:61ff:fe9d:f156", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80:0:0:0:204:61ff:fe9d:f156", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::204:61ff:fe9d:f156", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append((":", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::ffff:c000:280", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("2001:0db8:85a3:0000:0000:8a2e:0370:7334", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:db8:85a3:0:0:8a2e:370:7334", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:db8:85a3::8a2e:370:7334", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:0000:0000:0000:0000:1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:0000:0000:0000::1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:0:0:0:0:1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:0:0::1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8::1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:db8::1428:57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0000:0000:0000:0000:0000:0000:0000:0001", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::ffff:0c22:384e", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:1234:0000:0000:0000:0000:0000", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:0db8:1234:ffff:ffff:ffff:ffff:ffff", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("2001:db8:a::123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("fe80::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("123", {'domainname':False, 'hostname':False, 'label':True, 'ipv4':False, 'ipv6':False}, "")) #hm
    test_vectors.append(("ldkfj", {'domainname':True, 'hostname':True, 'label':True, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("2001::FFD3::57ab", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("2001:db8:85a3::8a2e:37023:7334", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("2001:db8:85a3::8a2e:370k:7334", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1:2:3:4:5:6:7:8:9", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1::2::3", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1:::3:4:5", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1:2:3::4:5:6:7:8:9", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333:4444::6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222:3333::5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111:2222::4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("1111::3333:4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::2222:3333:4444:5555:6666:123.123.123.123", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0:0:0:0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0:0:0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0:0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0:0:0:0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0:0:0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0:0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:8888:9999", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:8888::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555:6666:7777:8888:9999", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111", {'domainname':False, 'hostname':False, 'label':True, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("11112222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:22223333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:33334444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:44445555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:55556666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:66667777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:77778888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:::3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555:7777::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555:7777:8888::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444:5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444:5555:6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444:5555:6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444:5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444:5555:6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444:5555:6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555:6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555:6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444::6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444::6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:8888:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555:6666:7777:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:1.2.3.4.5", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':True, 'ipv6':False}, ""))
    test_vectors.append(("11112222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:22223333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:33334444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:44445555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:55556666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:66661.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:255255.255.255", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:255.255255.255", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:255.255.255255", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":2222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::2222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:::3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:::4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222::4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444:5555::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444:5555::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::.", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::..", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::...", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1...", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2..", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::1.2.3.", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::.2..", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::.2.3.", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::..3.", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::..3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::...4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666:7777::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::2222:3333:4444:5555:6666:7777:8888", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444:5555::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333:4444::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222:3333::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111:2222::4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":1111::3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::2222:3333:4444:5555:6666:1.2.3.4", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:7777:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append((":::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555:6666::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444:5555::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333:4444::6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222:3333::5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111:2222::4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("1111::3333:4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::3333:4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("::2222:3333:4444:5555:6666:7777:8888:", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))
    test_vectors.append(("0:a:b:c:d:e:f::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("::0:a:b:c:d:e:f", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, "syntactically correct, but bad form (::0:... could be combined)"))
    test_vectors.append(("a:b:c:d:e:f:0::", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':True}, ""))
    test_vectors.append(("':10.0.0.1", {'domainname':False, 'hostname':False, 'label':False, 'ipv4':False, 'ipv6':False}, ""))

    return test_vectors


if __name__ == '__main__':
    '''
    http://stackoverflow.com/questions/2180465/can-domain-name-subdomains-have-an-underscore-in-it
    http://serverfault.com/questions/162038/are-one-letter-host-names-valid

    "domain name" is the identifier of a resource in a DNS database
    "label" is the part of a domain name in between dots
    "hostname" is a special type of domain name which identifies Internet hosts

    hostnames:
    RFC 952: https://tools.ietf.org/html/rfc952
    DOD INTERNET HOST TABLE SPECIFICATION

    1. A "name" (Net, Host, Gateway, or Domain name) is a text string up
    to 24 characters drawn from the alphabet (A-Z), digits (0-9), minus
    sign (-), and period (.).  Note that periods are only allowed when
    they serve to delimit components of "domain style names". (See
    RFC-921, "Domain Name System Implementation Schedule", for
    background).  No blank or space characters are permitted as part of a
    name. No distinction is made between upper and lower case.  The first
    character must be an alpha character.  The last character must not be
    a minus sign or period. <snip> Single character names or nicknames
    are not allowed.

    RFC 1123: https://tools.ietf.org/html/rfc1123#page-13
    Requirements for Internet Hosts -- Application and Support

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

    DISCUSSION:
           This last requirement is not intended to specify the complete
           syntactic form for entering a dotted-decimal host number;
           that is considered to be a user-interface issue.  For
           example, a dotted-decimal number must be enclosed within
           "[ ]" brackets for SMTP mail (see Section 5.2.17).  This
           notation could be made universal within a host system,
           simplifying the syntactic checking for a dotted-decimal
           number.

           If a dotted-decimal number can be entered without such
           identifying delimiters, then a full syntactic check must be
           made, because a segment of a host domain name is now allowed
           to begin with a digit and could legally be entirely numeric
           (see Section 6.1.2.4).  However, a valid host name can never
           have the dotted-decimal form #.#.#.#, since at least the
           highest-level component label will be alphabetic.

    domain names:
    http://www.ietf.org/rfc/rfc2181
    Clarifications to the DNS Specification
    Name syntax

    Occasionally it is assumed that the Domain Name System serves only
    the purpose of mapping Internet host names to data, and mapping
    Internet addresses to host names.  This is not correct, the DNS is a
    general (if somewhat limited) hierarchical database, and can store
    almost any kind of data, for almost any purpose.

    The DNS itself places only one restriction on the particular labels
    that can be used to identify resource records.  That one restriction
    relates to the length of the label and the full name.  The length of
    any one label is limited to between 1 and 63 octets.  A full domain
    name is limited to 255 octets (including the separators).  The zero
    length full name is defined as representing the root of the DNS tree,
    and is typically written and displayed as ".".  Those restrictions
    aside, any binary string whatever can be used as the label of any
    resource record.  Similarly, any binary string can serve as the value
    of any record that includes a domain name as some or all of its value
    (SOA, NS, MX, PTR, CNAME, and any others that may be added).
    Implementations of the DNS protocols must not place any restrictions
    on the labels that can be used.  In particular, DNS servers must not
    refuse to serve a zone because it contains labels that might not be
    acceptable to some DNS client programs.  A DNS server may be
    configurable to issue warnings when loading, or even to refuse to
    load, a primary zone containing labels that might be considered
    questionable, however this should not happen by default.


    RFC 1123: https://tools.ietf.org/html/rfc1123#page-79
    Requirements for Internet Hosts -- Application and Support

    6.1.3.5  Extensibility
        DISCUSSION:
             The DNS defines domain name syntax very generally -- a
             string of labels each containing up to 63 8-bit octets,
             separated by dots, and with a maximum total of 255
             octets.  Particular applications of the DNS are
             permitted to further constrain the syntax of the domain
             names they use, although the DNS deployment has led to
             some applications allowing more general names.  In
             particular, Section 2.1 of this document liberalizes
             slightly the syntax of a legal Internet host name that
             was defined in RFC-952 [DNS:4].

    # https://www.ietf.org/rfc/rfc1035


    IPv4:
        https://tools.ietf.org/html/rfc780

    IPv6:
        https://tools.ietf.org/html/rfc5954
        https://tools.ietf.org/html/rfc2460
    '''

    class bcolors:
        HEADER = '\033[95m'
        OKBLUE = '\033[94m'
        OKGREEN = '\033[92m'
        WARNING = '\033[93m'
        FAIL = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'

    validator = HostnameValidator()
    regex_dict = validator.get_compiled_regex_dict()
    test_vectors = get_test_vectors()
    failure_dict = defaultdict(lambda: [0, []])
    for test_vector in test_vectors:
        msg = "\ntest_vector: " + test_vector[0]
        comment = test_vector[-1]
        if comment:
            msg = msg + '      #' + comment
        #print("\ntest_vector:", test_vector[0], '#', test_vector[-1])
        print(msg)
        vector_length = len(test_vector[0])
        pad = 50 - vector_length
        regex_test_answers = test_vector[1]
        for regex_name in regex_test_answers.keys():
            expected_result = regex_test_answers[regex_name]
            regex = regex_dict[regex_name]

            try:
                validator.test_thing(regex, test_vector[0])
            except AssertionError: # the test string was not matched by the regex
                if expected_result == True: #if the test is supposed to work
                    msg = str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + "  result: False" + bcolors.FAIL + " (FAIL)" + bcolors.ENDC + " ----ERROR----" + " was expected to work, but did not."
                    print(msg)
                    msg_short = str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + " result: False (FAIL)" + " was expected to match, but did not."
                    failure_dict[regex_name][0] = failure_dict[regex_name][0] + 1
                    failure_dict[regex_name][1].append("'" + test_vector[0] + "'" + pad*" " + msg_short)
                else:
                    print(str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + " result: False " + bcolors.OKGREEN + " (PASS)" + bcolors.ENDC)
                    pass    #test was supposed to fail, and it did
            else:
                if expected_result == False:    #if a test that was supposed to fail didnt
                    msg = str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + " result: True  " + bcolors.FAIL + " (FAIL)" + bcolors.ENDC + " ----ERROR----" + " was expected to fail, but did not."
                    print(msg)
                    msg_short = str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + " result: True  (FAIL)" + " was expected to not match, but did."
                    failure_dict[regex_name][0] = failure_dict[regex_name][0] + 1
                    failure_dict[regex_name][1].append("'" + test_vector[0] + "'" + pad*" " + msg_short)
                else:
                    print(str('[' + regex_name + ']').ljust(14) + " expected: " + str(expected_result).ljust(5) + " result: True " + bcolors.OKGREEN + "  (PASS)" + bcolors.ENDC)

    terminal_width = shutil.get_terminal_size((80, 20)).columns
    print("\nResult Summary:")

#    pprint.pprint(failure_dict, width=terminal_width)

    for key in failure_dict.keys():
        error_count = failure_dict[key][0]
        print(" ")
        print(key, "errors:", error_count)
        for report in failure_dict[key][1]:
            print("     ", report)

