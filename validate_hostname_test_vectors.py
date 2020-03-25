#!/usr/bin/env python3

def get_test_vectors():
    test_vectors = []

    # valid names that pass
    test_vectors.append(('lwn.net', True, "standard domain"))
    test_vectors.append(('lwn.net.', True, "standard domain with trailing dot"))
    test_vectors.append(('l-w-n.n-e-t', True, "valid use of dashes"))
    test_vectors.append(('l-w-n.XN--1QQW23A', True, "valid use of dashes"))
    test_vectors.append(('l-w-n.XN--1QQW23A.', True, "valid use of dashes with trailing dash"))
    test_vectors.append(('l-w-n.n-e-t.', True, "valid use of dashes, trailing dot"))
    test_vectors.append(('l'*63+'.net', True, "valid (max) name length"))

    test_vectors.append(('127.0.0.1', True, "valid use of ip"))
    test_vectors.append(('127.0.0.1.', True, "valid use of ip with trailing dot"))
    test_vectors.append(('127.000.0.1', True, "valid use of ip with leading 0s"))
    test_vectors.append(('127.000.0.1.', True, "valid use of ip with leading 0s and trailing dot"))

    # fails:
    test_vectors.append(('127.1', True, "valid use of implied octet"))          # most web browsers are ok with missing octets
    test_vectors.append(('127.0.1', True, "valid use of implied octet"))        # but this validation regex is not
                                                                                # cant use the ipaddress module to normalize
                                                                                # it does not like ipaddress.ip_address('127.1')
    test_vectors.append(('l'*64+'.net', False, "invalix > max name length"))
    #todo IPV6

    # invalid names that are correctly filtered out:
    test_vectors.append(('127.0000.0.1', False, "too many leading 0s"))
    test_vectors.append(('0127.0.0.1', False, "too many leading 0s"))
    test_vectors.append(('527.0.0.1', False, "out of ipv4 range >255.255.255.255"))

    test_vectors.append(('.lwn.net', False, "std domain with invalid leading dot"))
    test_vectors.append(('lwn..net', False, "std domain with invalid double dots"))
    test_vectors.append(('.lwn.net.', False, "std domain trailing dot with invalid leading dot"))
    test_vectors.append(('-lwn.net', False, "std domain with invalid leading dash"))
    test_vectors.append(('l-w-n.XN--1QQW23A-', False, "use of dashes with invalid trailing dash"))
    return test_vectors

if __name__ == '__main__':
    test_vectors = get_test_vectors()
    for test in test_vectors:
        print(test)

