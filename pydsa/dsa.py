"""
DSA Signature Algorithm - A simple implementation in Python

Copyright 2016 by Reiner Rottmann <reiner@rottmann.it>

Released under the MIT license.
"""
import os
import random


# Example DSA keypair - real world
dsa_key = {
    'Q': 1218442816993522937915646204915776994404649089503L,
    'P': 11220611807188583130302963536190351192186270126479330588604287699892081267588448305835704397593153801135202051719876685351614175538253684346816652027037363L,
    'G': 11189361631195852088154673407566885728548496486362662112597687161142104619469702160215294558351391466982303919803857229515093575816938371433954759500448775L,
    'pub': 4572510396595314270786423212039255215498677297795049756997099191729339616558419010431226927123876238239229467750410441342637393785565872285607741290303779L,
    'priv': 148102768779017960166999813987055538077373228390L}

# Example DSA keypair (simple) - for humans
dsa_key = {
    'Q': 11,
    'P': 23,
    'G': 4,
    'pub': 8,
    'priv': 7}


def _random_s(min, max):
    """
    Helper function to select a random number.
    :param min: smallest random number
    :param max: largest random number
    :return: random number
    """
    s = -1
    digits = random.randint(0, len(str(max)))
    while True:
        s = int(''.join(str(x) for x in map(ord, os.urandom(digits))))
        if s <= max and s >= 0:
            break
    return s


def _mod_inverse(a, b):
    """
    Helper function that calculates the Modular multiplicative inverse

    See https://en.wikipedia.org/wiki/Modular_multiplicative_inverse

    Implementation using Extended Euclidean algorithm by Eric taken from:
    http://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

    :param a: integer to calculate the mod inverse from
    :param b: the modulo to use
    :return: Modular multiplicative inverse
    """
    r = -1
    B = b
    A = a
    eq_set = []
    full_set = []
    mod_set = []

    # euclid's algorithm
    while r != 1 and r != 0:
        r = b % a
        q = b // a
        eq_set = [r, b, a, q * -1]
        b = a
        a = r
        full_set.append(eq_set)

    for i in range(0, 4):
        mod_set.append(full_set[-1][i])

    mod_set.insert(2, 1)
    counter = 0

    #extended euclid's algorithm
    for i in range(1, len(full_set)):
        if counter % 2 == 0:
            mod_set[2] = full_set[-1 * (i + 1)][3] * mod_set[4] + mod_set[2]
            mod_set[3] = full_set[-1 * (i + 1)][1]

        elif counter % 2 != 0:
            mod_set[4] = full_set[-1 * (i + 1)][3] * mod_set[2] + mod_set[4]
            mod_set[1] = full_set[-1 * (i + 1)][1]

        counter += 1

    if mod_set[3] == B:
        return mod_set[2] % B
    return mod_set[4] % B


def modexp_lr_k_ary(a, b, n, k=5):
    """
    Compute a ** b (mod n)
        K-ary LR method, with a customizable 'k'.

    This efficient modular exponentiation algorithm was
    implemented by Eli Bendersky

    http://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms/

    :param a: base
    :param b: exponent
    :param n: modulo
    :param k: customizeable k
    :return: Modular exponentation
    """
    base = 2 << (k - 1)
    # Precompute the table of exponents
    table = [1] * base
    for i in xrange(1, base):
        table[i] = table[i - 1] * a % n
    # Just like the binary LR method, just with a
    # different base
    #
    r = 1
    for digit in reversed(_digits_of_n(b, base)):
        for i in xrange(k):
            r = r * r % n
        if digit:
            r = r * table[digit] % n
    return r


def _digits_of_n(n, b):
    """

    Return the list of the digits in the base 'b'
    representation of n, from LSB to MSB

    This helper function is used by modexp_lr_k_ary and was
    implemented by Eli Bendersky.

    http://eli.thegreenplace.net/2009/03/28/efficient-modular-exponentiation-algorithms/

    :param n: integer
    :param b: base
    :return: number of digits in the base b
    """
    digits = []
    while n:
        digits.append(int(n % b))
        n /= b
    return digits

def dsa_sign(q, p, g, x, message):
    """
    Create a DSA signature of a message
    using the private part of a DSA keypair.

    The message is integer and usually a SHA-1 hash.

    public key: q,p,g, y
    public key: q,p,g, x

    Implemented using code snippets and explanations from:
    * http://www.herongyang.com/Cryptography/DSA-Introduction-Algorithm-Illustration-p23-q11.html
    * https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    * http://www.docjar.org/html/api/org/bouncycastle/crypto/

    >>> import hashlib
    >>> import dsa
    >>> m = hashlib.sha1()
    >>> m.update("ABCDE")
    >>> message = int("0x" + m.hexdigest(), 0)
    >>> dsa_key = {
    ...     'Q': 11,
    ...     'P': 23,
    ...     'G': 4,
    ...     'pub': 8,
    ...     'priv': 7}
    >>> sig = dsa.dsa_sign(dsa_key["Q"], dsa_key["P"], dsa_key["G"], dsa_key["priv"], message)
    >>> print len(sig)
    2

    :param q: selected prime divisor
    :param p: computed prime modulus: (p-1) mod q = 0
    :param g: computed:
              1 < g < p, g**q mod p = 1
              and
              g = h**((p-1)/q) mod p
    :param x: selected: 0 < x < q
    :param message: message to sign
    :return: DSA signature (s1,s2) sometimes called (r,s)
    """
    s = _random_s(1, q)
    s1 = 0
    s2 = 0
    while True:
        modexp = modexp_lr_k_ary(g, s, p)
        s1 = modexp % q
        if s1 == 0:
            s = _random_s(1, q)
            continue
        s = _mod_inverse(s, q) * (message + x * s1)
        s2 = s % q
        if s2 == 0:
            s = _random_s(1, q)
            continue
        return (int(s1), int(s2))


def dsa_verify(s1, s2, g, p, q, y, message):
    """
    Verify the DSA signature of a message
    using the public part of a DSA keypair.

    The message is integer and usually a SHA-1 hash.

    s1,s2: DSA signature; sometimes called (r,s)

    public key: q,p,g, y
    public key: q,p,g, x

    Implemented using code snippets and explanations from:
    * http://www.herongyang.com/Cryptography/DSA-Introduction-Algorithm-Illustration-p23-q11.html
    * https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    * http://www.docjar.org/html/api/org/bouncycastle/crypto/

    >>> import hashlib
    >>> import dsa
    >>> m = hashlib.sha1()
    >>> m.update("ABCDE")
    >>> message = int("0x" + m.hexdigest(), 0)
    >>> dsa_key = {
    ...     'Q': 11,
    ...     'P': 23,
    ...     'G': 4,
    ...     'pub': 8,
    ...     'priv': 7}
    >>> sig = (2,3)
    >>> print dsa.dsa_verify(sig[0], sig[1], dsa_key["G"], dsa_key["P"], dsa_key["Q"], dsa_key["pub"], message)
    True

    :param s1: DSA signature part 1, sometimes called r
    :param s2: DSA signature part 2, sometimes called s
    :param q: selected prime divisor
    :param p: computed prime modulus: (p-1) mod q = 0
    :param g: computed:
              1 < g < p, g**q mod p = 1
              and
              g = h**((p-1)/q) mod p
    :param y: computed: y = g**x mod p
    :param message: message to verify
    :return: True or False
    """
    if not s1 > 0:
        return False
    if not s1 < q:
        return False
    if not s2 > 0:
        return False
    if not s2 < q:
        return False
    w = _mod_inverse(s2, q)
    u1 = (message * w) % q
    u2 = (s1 * w) % q
    # v = (((g**u1)*(y**u2)) % p ) % q # correct formula but slooooow!
    # because of that, we use modulo arithmetic to calculate intermediate values:
    u1 = pow(g, u1, p)
    u2 = pow(y, u2, p)
    v = u1 * u2 % p % q
    if v == s1:
        return True
    return False


if __name__ == "__main__":
    import doctest
    doctest.testmod()
