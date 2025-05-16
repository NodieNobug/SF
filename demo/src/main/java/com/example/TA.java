package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Arrays;
import java.util.List;
import java.util.ArrayList;

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
    private List<BigInteger> R_t_history = new ArrayList<>(); // 新增：存储R_t的历史记录
    private BigInteger[] n_i; // 存储所有DO的ni值
    private BigInteger[] modelParamHashes; // 添加字段存储模型参数哈希值

    private static final int ORTHOGONAL_VECTOR_COUNT = 5;
    private static final int MODEL_SIZE = 5; // Define MODEL_SIZE with an appropriate value
    private double[][] orthogonalVectors;

    /**
     * 构造 TA 对象，numDO 表示参与联邦学习的 DO 数量。
     */
    public TA(int numDO, BigInteger[] modelParamHashes) { // 恢复 modelParamHashes 参数
        // 新增：根据DO数量动态设置门限值
        this.threshold = (numDO * 2) / 3; // 设置为总数的2/3，可以根据需求调整
        this.modelParamHashes = modelParamHashes; // 保存模型参数哈希值
        generateOrthogonalVectors();
        keyGeneration(numDO, modelParamHashes); // 恢复 modelParamHashes 参数
    }

    public void generateOrthogonalVectors() {
        // 随机生成一个矩阵
        orthogonalVectors = new double[ORTHOGONAL_VECTOR_COUNT][MODEL_SIZE];
        Random rand = new Random();

        // 生成第一个随机向量并归一化
        for (int j = 0; j < MODEL_SIZE; j++) {
            orthogonalVectors[0][j] = rand.nextGaussian();
        }
        orthogonalVectors[0] = normalizeVector(orthogonalVectors[0]);

        // 使用Gram-Schmidt生成其他正交向量
        for (int i = 1; i < ORTHOGONAL_VECTOR_COUNT; i++) {
            // 生成随机向量
            for (int j = 0; j < MODEL_SIZE; j++) {
                orthogonalVectors[i][j] = rand.nextGaussian();
            }

            // Gram-Schmidt正交化
            for (int k = 0; k < i; k++) {
                double projection = 0;
                double norm = 0;
                for (int j = 0; j < MODEL_SIZE; j++) {
                    projection += orthogonalVectors[i][j] * orthogonalVectors[k][j];
                    norm += orthogonalVectors[k][j] * orthogonalVectors[k][j];
                }
                double coef = projection / norm;

                // 正交化
                for (int j = 0; j < MODEL_SIZE; j++) {
                    orthogonalVectors[i][j] -= coef * orthogonalVectors[k][j];
                }
            }

            // 数值修正：将极小的向量投影值设为0，防止浮动误差
            orthogonalVectors[i] = normalizeVector(orthogonalVectors[i]);
        }

        // 输出生成的正交向量
        System.out.println("生成的正交向量组：");
        for (int i = 0; i < ORTHOGONAL_VECTOR_COUNT; i++) {
            System.out.println("向量" + i + ": " + Arrays.toString(orthogonalVectors[i]));
        }

        // 检查点积是否为0
        checkOrthogonality();
    }

    // 归一化向量
    private double[] normalizeVector(double[] vector) {
        double[] normalized = new double[vector.length];
        double norm = 0;
        for (double val : vector) {
            norm += val * val;
        }
        norm = Math.sqrt(norm);
        if (norm > 0) {
            for (int i = 0; i < vector.length; i++) {
                normalized[i] = vector[i] / norm;
            }
        }
        return normalized;
    }

    // 检查向量之间的点积是否为零
    private void checkOrthogonality() {
        for (int i = 0; i < ORTHOGONAL_VECTOR_COUNT; i++) {
            for (int j = i + 1; j < ORTHOGONAL_VECTOR_COUNT; j++) {
                double dotProduct = 0;
                for (int k = 0; k < MODEL_SIZE; k++) {
                    dotProduct += orthogonalVectors[i][k] * orthogonalVectors[j][k];
                }
                if (Math.abs(dotProduct) > 1e-10) {
                    System.out.println("向量 " + i + " 和 向量 " + j + " 的点积: " + dotProduct);
                }
            }
        }
    }

    private void keyGeneration(int numDO, BigInteger[] modelParamHashes) {
        // 确保 modelParamHashes 的长度与 numDO 一致
        if (modelParamHashes.length < numDO) {
            modelParamHashes = Arrays.copyOf(modelParamHashes, numDO);
            for (int i = modelParamHashes.length; i < numDO; i++) {
                modelParamHashes[i] = BigInteger.ONE; // 填充默认值
            }
        }

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

        System.out.println("n_i: " + Arrays.toString(n_i));

        // 生成随机 R_t，要求与 N 互质
        do {
            R_t = new BigInteger(bitLength, random);
        } while (!R_t.gcd(N).equals(BigInteger.ONE));

        // 确保每个DO的私钥和分片正确生成
        for (int i = 0; i < numDO; i++) {
            BigInteger sk = R_t.modPow(n_i[i].multiply(modelParamHashes[i]), N.multiply(N));
            doPrivateKeys.put(i, sk);
        }

        // 对每个 DO 的私钥进行秘密分片
        BigInteger modulus = N.multiply(N); // 使用N^2作为模数
        for (int i = 0; i < numDO; i++) {
            Map<Integer, BigInteger> shares = Threshold.splitSecret(doPrivateKeys.get(i), numDO, threshold, modulus);
            Map<Integer, BigInteger> distributedShares = new HashMap<>();
            for (int j = 0; j < numDO; j++) {
                if (j != i) {
                    distributedShares.put(j, shares.get(j + 1)); // 分发给其他DO
                }
            }
            doKeyShares.put(i, distributedShares);
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

    // 新增：获取特定轮次的R_t
    public BigInteger getR_t(int round) {
        if (round < 0 || round >= R_t_history.size()) {
            throw new IllegalArgumentException("Invalid round number");
        }
        return R_t_history.get(round);
    }

    // 新增：获取特定DO的ni值
    public BigInteger getNi(int doId) {
        return n_i[doId];
    }

    public BigInteger getY() {
        return y;
    }

    public double[][] getOrthogonalVectors() {
        return orthogonalVectors;
    }

    // 新增：获取模型参数哈希值的方法
    public BigInteger[] getModelParamHashes() {
        return modelParamHashes;
    }
}