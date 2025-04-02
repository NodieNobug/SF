package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;

class ImprovedPaillier {
    // 改进的 Paillier 加密算法
    // 该类实现了 Paillier 加密算法的基本功能，包括密钥生成、加密和解密
    private BigInteger N, g, lambda, u;
    private SecureRandom random = new SecureRandom();
    private int bitLength = 1024;

    public ImprovedPaillier() {
        keyGeneration();
    }

    private void keyGeneration() {
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        N = p.multiply(q);
        g = N.add(BigInteger.ONE);
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        u = g.modPow(lambda, N.multiply(N)).subtract(BigInteger.ONE).divide(N).modInverse(N);
    }

    public BigInteger encrypt(BigInteger x) {
        BigInteger r = new BigInteger(bitLength / 2, random);
        return g.modPow(x, N.multiply(N))
                .multiply(r.modPow(N, N.multiply(N)))
                .mod(N.multiply(N));
    }

    public BigInteger decrypt(BigInteger c) {
        BigInteger L = c.modPow(lambda, N.multiply(N)).subtract(BigInteger.ONE).divide(N);
        return L.multiply(u).mod(N);
    }

    public BigInteger getN() {
        return N;
    }
}