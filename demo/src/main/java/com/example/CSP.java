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
    private static final double CLUSTER_DISTANCE_THRESHOLD = 0.3;
    public Map<Integer, BigInteger> receivedCiphertexts = new HashMap<>();
    public Map<Integer, BigInteger[]> receivedModelParams = new HashMap<>();
    private Map<Integer, double[]> receivedProjections = new HashMap<>();
    public BigInteger aggregatedCiphertext;
    public BigInteger[] aggregatedModelParams;
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

                aggregatedModelParams[i] = aggregatedModelParams[i].multiply(params[i]).mod(N.multiply(N));
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
    public BigInteger decrypt(BigInteger aggregated, BigInteger lambda, BigInteger N, BigInteger u, BigInteger y) {
        BigInteger L = aggregated.modPow(lambda, N.multiply(N)).subtract(BigInteger.ONE).divide(N);
        return L.multiply(u).mod(N).mod(y);
    }

    /**
     * 解密聚合后的模型参数，并处理大数溢出问题
     */
    public double[] decrypt(BigInteger[] aggregated, BigInteger lambda, BigInteger N,
            BigInteger u, BigInteger y) {
        double[] decryptedParams = new double[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            BigInteger L = aggregated[i].modPow(lambda, N.multiply(N))
                    .subtract(BigInteger.ONE).divide(N);
            BigInteger decrypted = L.multiply(u).mod(N).mod(y);
            System.out.println("解密后的结果" + decrypted);
            System.out.println("y值是" + y);
            // 在BigInteger阶段处理负数情况
            if (decrypted.compareTo(y.divide(BigInteger.TWO)) > 0) {
                System.out.println("" + i + " 号参数溢出，进行修正.....");
                decrypted = decrypted.subtract(y);
            }

            // 将处理后的BigInteger转换为double（除以10^6恢复精度）
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
     * 基于点积结果比较和聚类分析进行投毒检测
     */
    public List<Integer> detectPoisoning(double[] aggregatedParams) {
        List<Integer> suspectedDOs = new ArrayList<>();

        // 1. 使用第一轮解密得到的聚合参数与正交向量组点积
        double[] cspDotProducts = new double[orthogonalVectors.length];
        for (int i = 0; i < orthogonalVectors.length; i++) {
            double dotProduct = 0;
            for (int j = 0; j < MODEL_SIZE; j++) {
                dotProduct += orthogonalVectors[i][j] * aggregatedParams[j];
            }
            cspDotProducts[i] = dotProduct;
        }

        // 2. 聚合DO上传的点积结果
        double[] doDotProducts = calculateAggregatedProjections();

        // 3. 比较两个结果是否一致（考虑浮点数误差）
        double threshold = 1e-3;
        System.out.println("\n第一轮聚合参数计算的点积结果: " + Arrays.toString(cspDotProducts));
        System.out.println("第二轮DO上传的点积结果聚合: " + Arrays.toString(doDotProducts));

        // 计算相对误差
        boolean consistent = true;
        for (int i = 0; i < cspDotProducts.length; i++) {
            double absoluteError = Math.abs(cspDotProducts[i] - doDotProducts[i]);
            double relativeError = 0;

            if (Math.abs(cspDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(cspDotProducts[i]);
            } else if (Math.abs(doDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(doDotProducts[i]);
            } else {
                relativeError = absoluteError;
            }

            if (relativeError > threshold) {
                consistent = false;
                System.out.printf("索引 %d 的相对误差: %.10f\n", i, relativeError);
                break;
            }
        }

        // 4. 进行聚类分析
        Map<Integer, double[]> normalizedProjections = new HashMap<>();
        List<Integer> doIds = new ArrayList<>(receivedProjections.keySet());
        for (int doId : doIds) {
            normalizedProjections.put(doId, normalizeVector(receivedProjections.get(doId)));
        }
        List<List<Integer>> clusters = clusterProjections(normalizedProjections, doIds);
        List<Integer> largestCluster = findLargestCluster(clusters);

        // 5. 根据结果综合判断
        if (!consistent) {
            System.out.println("警告：检测到DO在两轮中使用了不同的参数！");
            for (int doId : doIds) {
                if (!largestCluster.contains(doId)) {
                    suspectedDOs.add(doId);
                }
            }
        } else if (clusters.size() > 1) {
            System.out.println("DO在两轮使用了相同的参数，但通过聚类分析发现异常模式");
            for (int doId : doIds) {
                if (!largestCluster.contains(doId)) {
                    suspectedDOs.add(doId);
                }
            }
        }

        // 6. 输出分析结果
        System.out.println("\n检测分析结果：");
        System.out.println("参数一致性检查: " + (consistent ? "通过" : "未通过"));
        System.out.println("聚类数量: " + clusters.size());
        System.out.println("最大聚类大小: " + largestCluster.size());
        if (!suspectedDOs.isEmpty()) {
            System.out.println("可疑的DO: " + suspectedDOs);
        }

        return suspectedDOs;
    }

    // 保留必要的辅助方法
    private double[] calculateAggregatedProjections() {
        double[] aggregatedProjections = new double[orthogonalVectors.length];
        for (double[] projections : receivedProjections.values()) {
            for (int i = 0; i < orthogonalVectors.length; i++) {
                aggregatedProjections[i] += projections[i];
            }
        }
        return aggregatedProjections;
    }

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

    /**
     * 更新TA参数
     */
    public void updateTA(TA newTA) {
        this.ta = newTA;
        this.orthogonalVectors = newTA.getOrthogonalVectors();
        System.out.println("CSP 更新了TA的全局参数和正交向量");
    }

    /**
     * 清理CSP的状态
     */
    public void clearState() {
        receivedModelParams.clear();
        receivedProjections.clear();
        System.out.println("CSP 状态已清理，准备进入下一轮联邦学习");

    }
}