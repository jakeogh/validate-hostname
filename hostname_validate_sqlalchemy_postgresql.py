#!/usr/bin/env python3

from sqlalchemy import BigInteger
from sqlalchemy import CheckConstraint
from sqlalchemy import Column
from sqlalchemy import Unicode

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import class_mapper
from sqlalchemy.pool import NullPool

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.declarative import declared_attr

import time

DBNAME = "hostname_validate_temp_" + str(time.time()).split('.')[0]
ENGINE = create_engine("postgres://postgres@localhost/" + DBNAME, echo=True, poolclass=NullPool)   #for processes

def drop_database(dbname):
    with create_engine('postgresql://postgres@localhost/postgres', isolation_level='AUTOCOMMIT', echo=True).connect() as connection:
        connection.execute('DROP DATABASE ' + dbname)

def create_database(dbname):
    with create_engine('postgresql://postgres@localhost/postgres', isolation_level='AUTOCOMMIT', echo=True).connect() as connection:
        connection.execute('CREATE DATABASE ' + dbname)

def delete_and_recreate_database():
    try:
        drop_database(DBNAME)
    except:
        pass
    finally:
        create_database(DBNAME)

class BaseMixin(object):
    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    @classmethod
    def query(cls, session):
        return session.query_property()

Base = declarative_base(cls=BaseMixin)

class Hostname(Base):
    id = Column(BigInteger, primary_key=True, index=True)

#   hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                              # permits all numeric tld's, accepts invalid ips, accepts "..", but gets everything(?) else right. From freenode@#postgresql:RhodiumToad
#   hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*$"                  # prevent ".."
    hostname_constraint_regex = "^(?!.*-$)(?!.*-[.])(?!.*[.][.])(?:[A-Za-z0-9][A-Za-z0-9-]*)(?:[.][A-Za-z0-9][A-Za-z0-9-]*)*(?:[.A-Za-z0-9])$"  # prevent ".." and allow trailing .
    hostname_constraint = "name ~ \'" + hostname_constraint_regex + "\'"

    ip_constraint_regex = "^(([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))\.){3}([01]?[0-9]?[0-9]|2([0-4][0-9]|5[0-5]))$"                             # IP validation, fails on 127.1 http://stackoverflow.com/questions/106179/regular-expression-to-match-dns-hostname-or-ip-address
    ip_constraint = "name ~ \'" + ip_constraint_regex + "\'"

    constraint_regex = hostname_constraint_regex + '|' + ip_constraint_regex
    constraint = "name ~ \'" + constraint_regex + "\'"

#   print(constraint)

#   name = Column(Unicode(255), CheckConstraint(hostname_constraint), unique=False, nullable=False)
#   name = Column(Unicode(255), CheckConstraint(ip_constraint), unique=False, nullable=False)
    name = Column(Unicode(255), CheckConstraint(constraint), unique=False, nullable=False)

    def __repr__(self):
        return self.filename


def add_name(name):
    session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=ENGINE))

    file = Hostname(name=name)
    session.add(file)
    session.flush()
    session.commit()
    session.close()

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

    delete_and_recreate_database()
    Base.metadata.create_all(ENGINE)

    test_vectors = []
    test_vectors.append(('lwn.net', True))              #std domain
    test_vectors.append(('lwn.net.', True))             #std domain, trailing dot
    test_vectors.append(('l-w-n.n-e-t', True))          #valid use of dashes
    test_vectors.append(('l-w-n.XN--1QQW23A', True))    #valid use of dashes
    test_vectors.append(('l-w-n.XN--1QQW23A.', True))   #valid use of dashes with trailing dash
    test_vectors.append(('l-w-n.n-e-t.', True))         #valid use of dashes, trailing dot
    test_vectors.append(('l'*63+'.net', True))          #valid (max) name length

    test_vectors.append(('127.0.0.1', True))            #valid use of ip
    test_vectors.append(('127.0.0.1.', True))           #valid use of ip with trailing dot
    test_vectors.append(('127.000.0.1', True))          #valid use of ip with leading 0s
    test_vectors.append(('127.000.0.1.', True))         #valid use of ip with leading 0s and trailing dot

    # fails:
    test_vectors.append(('127.1', True))                #valid use of implied octet     # most web browsers are ok with missing octets
    test_vectors.append(('127.0.1', True))              #valid use of implied octet     # but this validation regex is not
                                                                                        # cant use the ipaddress module to normalize
                                                                                        # it does not like ipaddress.ip_address('127.1')
    test_vectors.append(('127.0000.0.1', False))        #too many leading 0s
    test_vectors.append(('0127.0.0.1', False))          #too many leading 0s
    test_vectors.append(('527.0.0.1', False))           #>255.255.255.255

    test_vectors.append(('.lwn.net', False))            #std domain with leading
    test_vectors.append(('lwn..net', False))            #std domain with double dots
    test_vectors.append(('.lwn.net.', False))           #std domain, trailing dot with leading dot
    test_vectors.append(('-lwn.net', False))            #std domain, leading dash
    test_vectors.append(('l-w-n.XN--1QQW23A-', False))  #use of dashes with trailing dash
    test_vectors.append(('l'*64+'.net', False))         # >max name length

    for item in test_vectors:
        try:
            add_name(item[0])
        except Exception as e:
            if item[1] == True: #if the test is supposed to work
                print(e)
                print("----ERROR----:", item, "was expected to work, but did not.\n")
#                quit()
            else:
#                print("got exception on", e, item[0])
                pass    #test was supposed to fail, and it did
        else:
            if item[1] == False:    #if a test that was supposed to fail didnt
                print("----ERROR----:", item, "was expected to fail, but did not.\n")
#               quit(0)

