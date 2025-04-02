package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

// TA 类：负责全局参数生成、为每个 DO 生成私钥，并将私钥秘密分片分发给其它 DO
class TA {
    // TA 类：负责全局参数生成、为每个 DO 生成私钥，并将私钥秘密分片分发给其它 DO
    public BigInteger N, g, h, lambda, u, y;
    public int bitLength = 1024;
    private SecureRandom random = new SecureRandom();
    // 保存每个 DO 的主私钥（key: DO 的编号）
    public Map<Integer, BigInteger> doPrivateKeys = new HashMap<>();

    // 保存每个 DO 的秘密分片，key: DO 的编号，value: 分发给其它 DO 的映射（key: 接收方 DO 编号, value: 分片值）
    public Map<Integer, Map<Integer, BigInteger>> doKeyShares = new HashMap<>();

    // TA 指定的哈希算法名称
    public String hashAlgorithm = "SHA-256";
    private int threshold; // 新增：门限值字段
    private BigInteger R_t; // 新增：存储R_t
    private BigInteger[] n_i; // 存储所有DO的ni值

    /**
     * 构造 TA 对象，numDO 表示参与联邦学习的 DO 数量。
     */
    public TA(int numDO, BigInteger[] modelParamHashes) { // 恢复 modelParamHashes 参数
        // 新增：根据DO数量动态设置门限值
        this.threshold = (numDO * 2) / 3; // 设置为总数的2/3，可以根据需求调整
        keyGeneration(numDO, modelParamHashes); // 恢复 modelParamHashes 参数
    }

    private void keyGeneration(int numDO, BigInteger[] modelParamHashes) { // 恢复 modelParamHashes 参数
        // 生成大素数 p, q
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        N = p.multiply(q);
        g = N.add(BigInteger.ONE);

        // 选取随机数 k 与 y，其中 y 与 k 互质
        BigInteger k = new BigInteger(bitLength, random);
        do {
            y = new BigInteger(bitLength / 3, random);
        } while (!y.gcd(k).equals(BigInteger.ONE));
        h = g.modPow(y, N.multiply(N));

        // 计算 λ = lcm(p-1, q-1)
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
        u = g.modPow(lambda, N.multiply(N)).subtract(BigInteger.ONE).divide(N).modInverse(N);

        // 为每个 DO 生成私钥：参考原始代码中 SK_DO 的生成
        n_i = new BigInteger[numDO];
        BigInteger sum = BigInteger.ZERO;
        for (int i = 0; i < numDO - 1; i++) {
            n_i[i] = new BigInteger(bitLength / 2, random);
            sum = sum.add(n_i[i]);
        }
        n_i[numDO - 1] = N.subtract(sum);

        // 生成随机 R_t，要求与 N 互质
        do {
            R_t = new BigInteger(bitLength, random);
        } while (!R_t.gcd(N).equals(BigInteger.ONE));

        // 修改：恢复原方案，直接在TA端计算完整私钥
        for (int i = 0; i < numDO; i++) {
            BigInteger sk = R_t.modPow(n_i[i].multiply(modelParamHashes[i]), N.multiply(N));
            doPrivateKeys.put(i, sk);
        }

        // 对每个 DO 的私钥进行秘密分片
        BigInteger modulus = N.multiply(N); // 修改：使用N^2作为模数，因为私钥在N^2下运算
        for (int i = 0; i < numDO; i++) {
            // System.out.println("DO " + i + " 的原始私钥: " + doPrivateKeys.get(i));
            Map<Integer, BigInteger> shares = Threshold.splitSecret(doPrivateKeys.get(i), numDO, threshold, modulus);
            Map<Integer, BigInteger> distributedShares = new HashMap<>();
            for (int j = 0; j < numDO; j++) {
                if (j != i) {
                    distributedShares.put(j, shares.get(j + 1));
                }
            }
            doKeyShares.put(i, distributedShares);

            // TestDemo:验证生成的分片是否可以还原
            // Map<Integer, BigInteger> testShares = new HashMap<>();
            // for (int j = 1; j <= 5; j++) {
            // testShares.put(j, shares.get(j));
            // }
            // BigInteger reconstructed = Threshold.reconstructSecret(testShares, modulus);
            // System.out.println("验证重构: " + reconstructed.equals(doPrivateKeys.get(i)));
        }
    }

    // 以下接口用于向 DO 公开全局参数和哈希算法信息
    public BigInteger getN() {
        return N;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getLambda() {
        return lambda;
    }

    public BigInteger getU() {
        return u;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    // 新增：获取当前门限值的方法
    public int getThreshold() {
        return threshold;
    }

    // 新增：获取R_t的方法
    public BigInteger getR_t() {
        return R_t;
    }

    // 新增：获取特定DO的ni值
    public BigInteger getNi(int doId) {
        return n_i[doId];
    }
}