package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

// CSP 类：负责聚合各个 DO 上传的密文、判断是否有 DO 掉线、请求备用分片恢复私钥，并进行解密
class CSP {
    private TA ta;
    private int totalDO;
    private static final int MODEL_SIZE = 5;
    // 存储来自各 DO 的加密数据（key: DO id, value: 密文）
    public Map<Integer, BigInteger> receivedCiphertexts = new HashMap<>();
    // 存储来自各DO的加密模型参数（key: DO id, value: 加密参数数组）
    public Map<Integer, BigInteger[]> receivedModelParams = new HashMap<>();
    // 聚合后的密文
    public BigInteger aggregatedCiphertext;
    // 聚合后的密文数组
    public BigInteger[] aggregatedModelParams;

    public CSP(TA ta, int totalDO) {
        this.ta = ta;
        this.totalDO = totalDO;
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
}