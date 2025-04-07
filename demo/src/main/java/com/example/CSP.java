package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;

// CSP 类：负责聚合各个 DO 上传的密文、判断是否有 DO 掉线、请求备用分片恢复私钥，并进行解密
class CSP {
    private TA ta;
    private int totalDO;
    private static final int MODEL_SIZE = 5;
    private static final double POISON_THRESHOLD = 0.1; // 投毒检测阈值
    private static final double COSINE_THRESHOLD = 0.5; // 余弦相似度阈值
    private static final double CLUSTER_DISTANCE_THRESHOLD = 0.3; // 聚类距离阈值
    private static final double GLOBAL_WEIGHT = 0.8; // 全局模型参数权重
    private static final double LOCAL_WEIGHT = 0.2; // DO上传参数权重
    // 存储来自各 DO 的加密数据（key: DO id, value: 密文）
    public Map<Integer, BigInteger> receivedCiphertexts = new HashMap<>();
    // 存储来自各DO的加密模型参数（key: DO id, value: 加密参数数组）
    public Map<Integer, BigInteger[]> receivedModelParams = new HashMap<>();
    // 存储来自各DO的投影结果（key: DO id, value: 投影数组）
    private Map<Integer, double[]> receivedProjections = new HashMap<>();
    // 聚合后的密文
    public BigInteger aggregatedCiphertext;
    // 聚合后的密文数组
    public BigInteger[] aggregatedModelParams;
    // 正交向量
    private double[][] orthogonalVectors;

    public CSP(TA ta, int totalDO) {
        this.ta = ta;
        this.totalDO = totalDO;
        this.orthogonalVectors = ta.getOrthogonalVectors();
    }

    /**
     * 接收来自 DO 的加密数据
     */
    public void receiveData(int doId, BigInteger ciphertext) {
        receivedCiphertexts.put(doId, ciphertext);
    }

    /**
     * 接收来自DO的加密模型参数
     */
    public void receiveData(int doId, BigInteger[] encryptedParams) {
        receivedModelParams.put(doId, encryptedParams);
    }

    /**
     * 接收来自DO的投影结果
     */
    public void receiveProjections(int doId, double[] projections) {
        receivedProjections.put(doId, projections);
    }

    /**
     * 聚合所有DO的加密模型参数
     */
    public BigInteger[] aggregate(BigInteger N) {
        aggregatedModelParams = new BigInteger[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            aggregatedModelParams[i] = BigInteger.ONE;
            for (BigInteger[] params : receivedModelParams.values()) {
                aggregatedModelParams[i] = aggregatedModelParams[i].multiply(params[i])
                        .mod(N.multiply(N));
            }
        }
        return aggregatedModelParams;
    }

    /**
     * 解密聚合后的数据。这里采用 ImprovedPaillier 中的解密思路：
     * L = (aggregated^(lambda) mod N^2 - 1) / N，然后乘以 u，再 mod y 得到结果。
     * allPrivateKeys 为所有 DO 的私钥列表（包括恢复后的掉线 DO 私钥）。
     * 注意：示例中为简化实现，未对各私钥进行联合分布式解密。
     */
    public BigInteger decrypt(BigInteger aggregated, BigInteger lambda, BigInteger N, BigInteger u, BigInteger y,
            List<BigInteger> allPrivateKeys) {
        BigInteger L = aggregated.modPow(lambda, N.multiply(N)).subtract(BigInteger.ONE).divide(N);
        return L.multiply(u).mod(N).mod(y);
    }

    /**
     * 解密聚合后的模型参数
     */
    public double[] decrypt(BigInteger[] aggregated, BigInteger lambda, BigInteger N,
            BigInteger u, BigInteger y, List<BigInteger> allPrivateKeys) {
        double[] decryptedParams = new double[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            BigInteger L = aggregated[i].modPow(lambda, N.multiply(N))
                    .subtract(BigInteger.ONE).divide(N);
            BigInteger decrypted = L.multiply(u).mod(N).mod(y);
            // 将BigInteger转换回double（除以10^6恢复精度）
            decryptedParams[i] = decrypted.doubleValue() / 1000000.0;
        }
        return decryptedParams;
    }

    /**
     * 计算模型参数的平均值
     * 
     * @param aggregatedParams 聚合后的参数
     * @param activeCount      在线的DO数量
     */
    public double[] calculateAverage(double[] aggregatedParams, int activeCount) {
        double[] averagedParams = new double[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            averagedParams[i] = aggregatedParams[i] / activeCount;
        }
        return averagedParams;
    }

    /**
     * 判断是否有 DO 掉线：即收到的密文数量是否少于 totalDO。
     */
    public boolean hasDropout() {
        return receivedCiphertexts.size() < totalDO;
    }

    /**
     * 如果检测到某个 DO 掉线，则向在线 DO 请求 TA 分发的该 DO 的私钥分片，
     * 并利用拉格朗日插值恢复出掉线 DO 的私钥。
     *
     * availableDOs：在线的 DO 列表（不包含掉线 DO）。
     */
    public BigInteger recoverMissingPrivateKey(int missingDOId, List<DO> availableDOs) {
        Map<Integer, BigInteger> shares = new HashMap<>();
        for (DO doObj : availableDOs) {
            int xValue = doObj.getId() + 1; // 确保 x 值唯一且与 DO ID 对应
            BigInteger share = doObj.uploadKeyShare(missingDOId);
            shares.put(xValue, share);
        }
        // 使用TA的门限值
        if (shares.size() < ta.getThreshold()) {
            throw new IllegalStateException("分片数量不足" + ta.getThreshold() + "个，无法恢复私钥");
        }
        BigInteger recoveredKey = Threshold.reconstructSecret(shares, ta.getN()); // 确保模数一致
        System.out.println("收集到 " + shares.size() + " 个分片");
        // System.out.println("恢复掉线 DO " + missingDOId + " 的私钥为: " + recoveredKey);
        return recoveredKey;
    }

    /**
     * 使用恢复的私钥对全 0 虚构数据进行加密
     */
    public BigInteger encryptZeroData(BigInteger recoveredKey, BigInteger N, BigInteger g, BigInteger h) {
        SecureRandom random = new SecureRandom();
        BigInteger r = new BigInteger(N.bitLength() / 2, random);
        BigInteger zeroData = BigInteger.ZERO;
        return g.modPow(zeroData, N.multiply(N))
                .multiply(h.modPow(r, N.multiply(N)))
                .multiply(recoveredKey)
                .mod(N.multiply(N));
    }

    /**
     * 恢复多个掉线 DO 的私钥
     */
    public Map<Integer, BigInteger> recoverMissingPrivateKeys(List<Integer> missingDOIds, List<DO> availableDOs) {
        Map<Integer, BigInteger> recoveredKeys = new HashMap<>();
        BigInteger modulus = ta.getN().multiply(ta.getN()); // 修改：使用N^2作为模数

        for (int missingDOId : missingDOIds) {
            System.out.println("\n开始恢复 DO " + missingDOId + " 的私钥\n");
            Map<Integer, BigInteger> shares = new HashMap<>();

            for (DO doObj : availableDOs) {
                int xValue = doObj.getId() + 1;
                BigInteger share = doObj.uploadKeyShare(missingDOId);
                if (share != null) {
                    shares.put(xValue, share);
                }
            }

            if (shares.size() < ta.getThreshold()) {
                throw new IllegalStateException("分片数量不足" + ta.getThreshold() + "个，当前只有: " + shares.size() + "个");
            }

            BigInteger recoveredKey = Threshold.reconstructSecret(shares, modulus); // 使用N^2作为模数
            // System.out.println("原始私钥: " + ta.doPrivateKeys.get(missingDOId));
            // System.out.println("恢复的私钥: " + recoveredKey);
            // System.out.println("私钥恢复正确性验证: " +
            // recoveredKey.equals(ta.doPrivateKeys.get(missingDOId)));

            recoveredKeys.put(missingDOId, recoveredKey);
        }
        return recoveredKeys;
    }

    /**
     * 通过聚合结果反推正交向量组
     * 
     * @param decryptedParams 解密后的聚合明文M
     */
    public double[][] recoverOrthogonalVectors(double[] decryptedParams) {
        double[] sumProjections = calculateAggregatedProjections();
        System.out.println("\n开始反推正交向量...");
        System.out.println("所有DO模型参数的聚合值M: " + Arrays.toString(decryptedParams));

        double[][] recoveredVectors = new double[MODEL_SIZE][MODEL_SIZE];

        // 从投影结果还原正交向量
        // sumProjections中存储了所有DO对每个正交向量每个元素的乘积结果之和
        for (int i = 0; i < MODEL_SIZE; i++) { // 对每个正交向量
            for (int j = 0; j < MODEL_SIZE; j++) { // 对每个元素
                // 索引计算：i是当前正交向量的索引，j是元素位置
                int projectionIndex = i * MODEL_SIZE + j;

                // 如果当前维度的聚合值不为0，则进行还原
                if (Math.abs(decryptedParams[j]) > 1e-10) {
                    // 还原：投影结果除以对应维度的模型参数聚合值
                    recoveredVectors[i][j] = sumProjections[projectionIndex] / decryptedParams[j];
                } else {
                    recoveredVectors[i][j] = 0;
                }
            }
            // 归一化每个恢复的向量
            recoveredVectors[i] = normalizeVector(recoveredVectors[i]);
        }

        // System.out.println("\n反推得到的正交向量组:");
        // for (int i = 0; i < MODEL_SIZE; i++) {
        // System.out.println("向量" + i + ": " + Arrays.toString(recoveredVectors[i]));
        // }

        return recoveredVectors;
    }

    private double[] calculateAggregatedProjections() {
        // 新的投影结果大小为 MODEL_SIZE * MODEL_SIZE
        double[] aggregatedProjections = new double[MODEL_SIZE * MODEL_SIZE];

        // 累加所有DO的投影结果
        for (double[] projections : receivedProjections.values()) {
            for (int i = 0; i < projections.length; i++) {
                aggregatedProjections[i] += projections[i];
            }
        }
        return aggregatedProjections;
    }

    /**
     * 验证向量组是否正交
     * 
     * @param vectors 要验证的向量组
     * @return 如果向量组正交返回true，否则返回false
     */
    public boolean verifyOrthogonality(double[][] vectors, double epsilon) {
        for (int i = 0; i < vectors.length; i++) {
            for (int j = i + 1; j < vectors.length; j++) {
                double dotProduct = 0.0;
                for (int k = 0; k < vectors[i].length; k++) {
                    dotProduct += vectors[i][k] * vectors[j][k];
                }
                if (Math.abs(dotProduct) > epsilon) {
                    return false; // 不正交
                }
            }
        }
        return true; // 正交
    }

    /**
     * 仅基于投影结果进行投毒检测
     */
    public List<Integer> detectPoisoning(double[] aggregatedParams) {
        List<Integer> suspectedDOs = new ArrayList<>();
        int totalDOs = receivedProjections.size();
        List<Integer> doIds = new ArrayList<>(receivedProjections.keySet());

        // 对所有DO的投影结果进行归一化
        Map<Integer, double[]> normalizedProjections = new HashMap<>();
        for (int i = 0; i < totalDOs; i++) {
            int doId = doIds.get(i);
            double[] proj = receivedProjections.get(doId);
            normalizedProjections.put(doId, normalizeVector(proj));
        }

        // 使用聚类方法检测异常
        List<List<Integer>> clusters = clusterProjections(normalizedProjections, doIds);
        List<Integer> largestCluster = findLargestCluster(clusters);

        // 将不在最大聚类中的DO标记为可疑
        for (int doId : doIds) {
            if (!largestCluster.contains(doId)) {
                suspectedDOs.add(doId);
            }
        }

        // 打印聚类结果
        System.out.println("\n投影结果聚类分析：");
        System.out.println("检测到的聚类数量: " + clusters.size());
        System.out.println("最大聚类大小: " + largestCluster.size());
        System.out.println("可疑的DO: " + suspectedDOs);

        return suspectedDOs;
    }

    /**
     * 对投影结果进行聚类
     */
    private List<List<Integer>> clusterProjections(Map<Integer, double[]> normalizedProjections, List<Integer> doIds) {
        List<List<Integer>> clusters = new ArrayList<>();
        Set<Integer> visitedDOs = new HashSet<>();

        for (int doId : doIds) {
            if (visitedDOs.contains(doId))
                continue;

            List<Integer> currentCluster = new ArrayList<>();
            expandCluster(doId, normalizedProjections, visitedDOs, currentCluster, doIds);

            if (!currentCluster.isEmpty()) {
                clusters.add(currentCluster);
            }
        }
        return clusters;
    }

    private List<Integer> findLargestCluster(List<List<Integer>> clusters) {
        return clusters.stream()
                .max((c1, c2) -> Integer.compare(c1.size(), c2.size()))
                .orElse(new ArrayList<>());
    }

    /**
     * 计算所有DO投影结果的聚合值
     */

    private void expandCluster(int currentDoId,
            Map<Integer, double[]> normalizedProjections,
            Set<Integer> visitedDOs,
            List<Integer> currentCluster,
            List<Integer> allDoIds) {

        visitedDOs.add(currentDoId);
        currentCluster.add(currentDoId);

        for (int neighborId : allDoIds) {
            if (visitedDOs.contains(neighborId))
                continue;

            double similarity = calculateCosineSimilarity(
                    normalizedProjections.get(currentDoId),
                    normalizedProjections.get(neighborId));

            if (similarity > (1 - CLUSTER_DISTANCE_THRESHOLD)) {
                expandCluster(neighborId, normalizedProjections, visitedDOs, currentCluster, allDoIds);
            }
        }
    }

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

    private double calculateCosineSimilarity(double[] vector1, double[] vector2) {
        double dotProduct = 0;
        double norm1 = 0;
        double norm2 = 0;
        for (int i = 0; i < vector1.length; i++) {
            dotProduct += vector1[i] * vector2[i];
            norm1 += vector1[i] * vector1[i];
            norm2 += vector2[i] * vector2[i];
        }
        double norm = Math.sqrt(norm1) * Math.sqrt(norm2);
        return norm == 0 ? 0 : dotProduct / norm;
    }

}