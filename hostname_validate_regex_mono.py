#!/usr/bin/env python3
# https://github.com/jakeogh/hostname-validate
import re
import pprint

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class HostnameValidator():
    def __init__(self):
        self.regex_names = ['name', 'ipv4', 'ipv6', 'all']
        #self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                              # permits all numeric tld's, accepts invalid ips, accepts "..", but gets everything(?) else right. From freenode@#postgresql:RhodiumToad
        #self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                  # prevent ".."
        #self.hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"  # prevent ".." and allow trailing .
        #self.hostname_constraint_regex = r"""(?=^.{1,63}$)^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$""" # limit len to 63  From freenode@#python:bok^3
        self.name_constraint_regex = r"""
                                            (?=^.{1,255}$)                                          # limit total hostname length to 255
                                            ^(?!.*-$)                                               # trailing - are not valid
                                            ^(?!.*\.[0-9]*$)                                        # trailing 0-9 are not valid, there are no all numeric TLD's and if there were it would break things
                                            (?!.*-[.])                                              # no - before a .
                                            (?!.*[.][.])                                            # no repeating .
                                            (?:[A-Za-z0-9][A-Za-z0-9-]*)
                                            (?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"""

                                            #^(?!.*\.$)                                              # trailing . are not valid

        #self.ipv4_constraint_regex = r"""^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"""                      # IP validation, fails on 127.1 http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
        self.ipv4_constraint_regex = r"""                                                                                                                 # add max ipv4 length 3*4+3*1 = 15
                                    (?=^.{1,14}$)
                                    ^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.)
                                    {3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"""


        # https://gist.github.com/syzdek/6086792
        self.ipv6_constraint_regex = r"""(
                                        ([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|          # 1:2:3:4:5:6:7:8
                                        ([0-9a-fA-F]{1,4}:){1,7}:|                         # 1::                              1:2:3:4:5:6:7::
                                        ([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|         # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
                                        ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|  # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
                                        ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|  # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
                                        ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|  # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
                                        ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|  # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
                                        [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|       # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
                                        :((:[0-9a-fA-F]{1,4}){1,7}|:)|                     # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
                                        fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|     # fe80::7:8%eth0   fe80::7:8%1     (link-local IPv6 addresses with zone index)
                                        ::(ffff(:0{1,4}){0,1}:){0,1}
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|          # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255  (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
                                        ([0-9a-fA-F]{1,4}:){1,4}:
                                        ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                                        (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])           # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33 (IPv4-Embedded IPv6 Address)
                                        )"""

        self.all_constraint_regex = self.name_constraint_regex + '|' + self.ipv4_constraint_regex + '|' + self.ipv6_constraint_regex
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

def test_hostname(regex, name):
    answer = regex.fullmatch(name)
    if answer == None:
        raise AssertionError
    return True

def get_test_vectors():
    test_vectors = []

    # valid names that pass:
    #test_vectors.append(('lwn.net', True, "standard domain"))
    test_vectors.append(('lwn.net', {'name':True, 'ipv4':False, 'ipv6':False}, "standard domain"))
    test_vectors.append(('net', {'name':True, 'ipv4':False, 'ipv6':False}, "standard domain without a ."))
    test_vectors.append(('3.net', {'name':True, 'ipv4':False, 'ipv6':False}, "standard domain starting with a number"))
    test_vectors.append(('LWN.NET', {'name':True, 'ipv4':False, 'ipv6':False}, "standard domain uppercase"))
    test_vectors.append(('l-w-n.n-e-t', {'name':True, 'ipv4':False, 'ipv6':False}, "valid use of dashes"))
    test_vectors.append(('l-w-n.XN--1QQW23A', {'name':True, 'ipv4':False, 'ipv6':False}, "valid use of dashes"))
    test_vectors.append(('l'*59+'.net', {'name':True, 'ipv4':False, 'ipv6':False}, "valid (63 max) name length")) # 59 + 4 = 63
    # http://archive.oreilly.com/pub/post/the_worlds_longest_domain_name.html
    test_vectors.append(('www.thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com', {'name':True, 'ipv4':False, 'ipv6':False}, "valid real world 71 char name"))
    test_vectors.append(('3.141592653589793238462643383279502884197169399375105820974944592.com', {'name':True, 'ipv4':False, 'ipv6':False}, "valid real world 69 char name with all numbers except for the TLD"))
    test_vectors.append(('l'*251+'.net', {'name':True, 'ipv4':False, 'ipv6':False}, "valid 255 max length name")) # 251 + 4 = 255

    # valid IPV4 that pass:
    test_vectors.append(('127.0.0.1', {'name':False, 'ipv4':True, 'ipv6':False}, "valid use of ip"))
    test_vectors.append(('127.000.0.1', {'name':False, 'ipv4':True, 'ipv6':False}, "valid use of ip with leading 0s"))

    # valid IPV6 that pass:
    test_vectors.append(('0:0:0:0:0:0:0:1', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 loopback"))
    test_vectors.append(('::1', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 loopback abbreviated"))
    test_vectors.append(('::', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 0:0:0:0:0:0:0:0"))
    test_vectors.append(('2001:4860:4860::8888', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 version of 8.8.8.8"))
    test_vectors.append(('2001:0000:0234:C1AB:0000:00A0:AABC:003F', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 standard address")) # http://www.zytrax.com/tech/protocols/ipv6.html
    test_vectors.append(('2001::0234:C1ab:0:A0:aabc:003F', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 standard address with single 0 dropped"))

    # valid ipv6 that are incorrectly rejected
    test_vectors.append(('2001:db8:0:0:0:0:FFFF:192.168.0.5', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address")) # http://www.zytrax.com/tech/protocols/ipv6.html
    test_vectors.append(('2001:db8:0::0:0:FFFF:192.168.0.5', {'name':False, 'ipv4':False, 'ipv6':True}, "IPV6 hybrid address with single 0 dropped"))

    # invalid ipv4 that are correctly rejected:
    # ipv4 has no RFC spec to drop octets, it's a mess: http://superuser.com/questions/486788/why-does-pinging-192-168-072-only-2-dots-return-a-response-from-192-168-0-58
    test_vectors.append(('127.1', {'name':False, 'ipv4':False, 'ipv6':False}, "valid use of implied octet"))          # most web browsers are ok with missing octets
    test_vectors.append(('127.0.1', {'name':False, 'ipv4':False, 'ipv6':False}, "valid use of implied octet"))        # but this validation regex is not
    test_vectors.append(('127.0.0.1.', {'name':False, 'ipv4':False, 'ipv6':False}, "ipv4 with invalid trailing dot"))
    test_vectors.append(('127.000.0.1.', {'name':False, 'ipv4':False, 'ipv6':False}, "valid use of ip with leading 0s and invalid trailing dot"))

    # invalid ipv6 that are correctly rejected
    test_vectors.append(('2001::0234:C1ab::A0:aabc:003F', {'name':False, 'ipv4':False, 'ipv6':False}, "IPV6 one or more zeros entries can be omitted entirely but only once in an address"))
    test_vectors.append(('2001:db8:0:::0:FFFF:192.168.0.5', {'name':False, 'ipv4':False, 'ipv6':False}, "invlaid IPV6 hybrid address with two 0's dropped"))

    # invalid ipv4 that are correctly rejected:
    test_vectors.append(('127.0000.0.1', {'name':False, 'ipv4':False, 'ipv6':False}, "too many leading 0s"))
    test_vectors.append(('0127.0.0.1', {'name':False, 'ipv4':False, 'ipv6':False}, "too many leading 0s"))
    test_vectors.append(('127.0.0.0.1', {'name':False, 'ipv4':False, 'ipv6':False}, "too many octs"))
    test_vectors.append(('127.111.111.1111', {'name':False, 'ipv4':False, 'ipv6':False}, "ipv4 too long"))
    test_vectors.append(('527.0.0.1', {'name':False, 'ipv4':False, 'ipv6':False}, "ipv4 out of range >255.255.255.255"))

    # invalid names that are correctly rejected:
    test_vectors.append(('lwn.net.', {'name':False, 'ipv4':False, 'ipv6':False}, "standard domain with invalid trailing dot")) #RFC952 implies this should not be valid...
    test_vectors.append(('l-w-n.XN--1QQW23A.', {'name':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes with invalid trailing dot"))
    test_vectors.append(('l-w-n.n-e-t.', {'name':False, 'ipv4':False, 'ipv6':False}, "valid use of dashes with invalid trailing dot"))
    test_vectors.append(('l wn.net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid space"))
    test_vectors.append(('l	wn.net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid tab"))
    test_vectors.append(('.lwn.net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid leading dot"))
    test_vectors.append(('lwn..net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid double dots"))
    test_vectors.append(('.lwn.net.', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain invalid trailing dot with invalid leading dot"))
    test_vectors.append(('-lwn.net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid leading dash"))
    test_vectors.append(('lwn-.net', {'name':False, 'ipv4':False, 'ipv6':False}, "std domain with invalid dash before a dot"))
    test_vectors.append(('l-w-n.XN--1QQW23A-', {'name':False, 'ipv4':False, 'ipv6':False}, "use of dashes with invalid trailing dash"))
    test_vectors.append(('l'*252+'.net', {'name':False, 'ipv4':False, 'ipv6':False}, "invalid >255 max length name")) # 252 + 4 = 256
    test_vectors.append(('☃.net', {'name':False, 'ipv4':False, 'ipv6':False}, "invalid UTF8 char in hostname"))
    test_vectors.append(('lwn.111', {'name':False, 'ipv4':False, 'ipv6':False}, "invalid all numeric TLD")) #otherwise it's not possible to distinguish 127.111.111.1111 from a domain

    return test_vectors


if __name__ == '__main__':
    '''
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
    '''

    validator = HostnameValidator()
    regex_dict = validator.get_compiled_regex_dict()
    test_vectors = get_test_vectors()

    for test_vector in test_vectors:
        print("\ntest_vector:", test_vector[0])
        print(test_vector[-1])
        regex_test_answers = test_vector[1]
        for regex_name in regex_test_answers.keys():
            expected_result = regex_test_answers[regex_name]
            regex = regex_dict[regex_name]

            try:
                test_hostname(regex, test_vector[0])
            except AssertionError: # the test string was not matched by the regex
                if expected_result == True: #if the test is supposed to work
                    print(regex_name, "expected:", expected_result, "result: False" + bcolors.FAIL, " (FAIL)", bcolors.ENDC + "----ERROR----", "was expected to work, but did not.")
                else:
                    print(regex_name, "expected:", expected_result, "result: False" + bcolors.OKGREEN, "(PASS)", bcolors.ENDC)
                    pass    #test was supposed to fail, and it did
            else:
                if expected_result == False:    #if a test that was supposed to fail didnt
                    print(regex_name, "expected:", expected_result, "result: True" + bcolors.FAIL, " (FAIL)", bcolors.ENDC + "----ERROR----", "was expected to fail, but did not.")
                else:
                    print(regex_name, "expected:", expected_result, "result: True" + bcolors.OKGREEN, "  (PASS)", bcolors.ENDC)



