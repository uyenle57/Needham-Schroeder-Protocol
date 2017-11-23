# -*- coding: utf-8 -*-#

import sys, re
import random, secrets
from array import *
from math import gcd
from itertools import combinations


class RsaEncryption():

    def __init__(self):
        pass

    def isPrime(self, x):
        """ Returns True if x is a prime number, else False """

        # 0 and 1 is not a prime number (requires two distinct natural numbers)
        if x <= 1 :
            return False

        for i in range(2, x-1):
            if x % i == 0: #even
                return False
        return True

    def generateRandPrime(self):
        """ Returns a randomly generated prime number between 2 and 100 """
        while True:
            self.num = secrets.randbelow(200)
            if(self.isPrime(self.num)):
                return self.num

    def calculateN(self, p, q):
        """ Returns key e by multiplying two primes p with q """
        return p * q

    def totient(self, p, q):
        """ Returns the totient key by calculating (p-1) * (q-1) """
        return (p-1) * (q-1)

    # Generate public key (e) using Euclidean algorithm
    def euclid(self, a, b):
        """ Returns the GCD of two numbers (largest integer divisible by both e and phi(n) is 1) """
        while b != 0:
            return gcd(b, a % b)
        else:
            return a

    def isCoPrime(self, list):
        """ Returns True if a number is coprime to phi(n), else False """
        for num, totient in combinations(list, 2):
            if(self.euclid(num, totient) == 1):
                return True
        return False

    # Generate private key (d) using Extended Euclidean algorithm
    # to calculate Modular multiplicative inverse
    def egcd(self, a, b):
        """ Returns 3 values:
                gcd is always 1 because a and b are relatively prime
                y is the modular multiplicative inverse of b % a
                x is the modular multiplicative inverse of a % b
        """
        if a == 0:
            return (b, 0, 1)
        else:
            gcd, y, x = self.egcd(b % a, a)
            return (gcd, x - (b // a) * y, y) # // is the integer division operator

    def modular_exponentiation(self, x, n, m):
        """ Returns x to the power of n modular m """
        return pow(x,n,m)

    def encrypt(self, plaintext, privateKey, totient):
        """ Return ciphertext by computing plaintext to the power of privateKey modular totient """
        c = self.modular_exponentiation(plaintext, privateKey, totient)
        return c
