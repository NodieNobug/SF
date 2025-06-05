// package com.example;

// import java.math.BigInteger;
// import java.nio.charset.StandardCharsets;
// import java.security.MessageDigest;
// import java.security.NoSuchAlgorithmException;
// import java.util.ArrayList;
// import java.util.Arrays;
// import java.util.HashMap;
// import java.util.List;
// import java.util.Map;

// // 测试类：包含多种场景的测试
// public class FederatedLearningTest {
// public static void main(String[] args) {
// System.out.println("Federated Learning Test 测试git是否可用");
// System.out.println("------------------------");

// int numDO = 8;
// // 模拟每个 DO 的模型参数字符串（保持不变）
// String[] modelParamStrings = {
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
// Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 })
// };
// BigInteger[] modelParamHashes = new BigInteger[numDO];
// // 计算每个模型参数字符串的哈希值
// try {
// MessageDigest digest = MessageDigest.getInstance("SHA-256");
// for (int i = 0; i < numDO; i++) {
// byte[] hashBytes =
// digest.digest(modelParamStrings[i].getBytes(StandardCharsets.UTF_8));
// modelParamHashes[i] = new BigInteger(1, hashBytes);
// }
// } catch (NoSuchAlgorithmException e) {
// e.printStackTrace();
// return;
// }

// // // ---------------- 场景1：正常流程测试 ----------------
// // System.out.println("----- 正常流程测试 -----");
// // runTestScenario(numDO, modelParamHashes, new ArrayList<>());

// // // // ---------------- 场景2：模拟单个 DO 掉线 ----------------
// // System.out.println("\n----- 掉线场景测试 -----");
// // System.out.println("总DO数量: " + numDO);
// // System.out.println("门限值: 5");
// // runTestScenario(numDO, modelParamHashes, Arrays.asList(1));

// // // // ---------------- 场景3：模拟多个 DO 掉线 ----------------
// System.out.println("\n----- 多 DO 掉线场景测试 -----");
// System.out.println("总DO数量: " + numDO);
// System.out.println("门限值: 5");
// System.out.println("掉线DO数量: 2");
// runTestScenario(numDO, modelParamHashes, Arrays.asList(2, 3));

// // ---------------- 场景4：一致性投毒测试 ----------------
// System.out.println("\n----- 一致性投毒测试场景 -----");
// System.out.println("总DO数量: " + numDO);
// System.out.println("投毒DO数量: 1");
// runConsistentPoisonTest(numDO, modelParamHashes);

// // ---------------- 场景5：伪装投毒测试 ----------------
// System.out.println("\n----- 伪装投毒测试场景 -----");
// System.out.println("总DO数量: " + numDO);
// System.out.println("投毒DO数量: 1");
// runDisguisedPoisonTest(numDO, modelParamHashes);
// }

// private static void runTestScenario(int numDO, BigInteger[] modelParamHashes,
// List<Integer> missingDOIds) {
// // TA 生成全局参数和每个 DO 的私钥及密钥分片
// TA ta = new TA(numDO, modelParamHashes); // 恢复传入modelParamHashes

// // 创建 DO 对象列表
// List<DO> doList = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// doList.add(new DO(i, ta));
// }

// // 创建 CSP 对象
// CSP csp = new CSP(ta, numDO);

// // 模拟 DO 加密并上传密文
// for (int i = 0; i < numDO; i++) {
// if (missingDOIds.contains(i)) {
// continue; // 模拟掉线
// }
// DO doObj = doList.get(i);
// doObj.trainModel();
// doObj.encryptData(ta.getN(), ta.getG(), ta.getH());
// csp.receiveData(i, doObj.getEncryptedModelParams());
// }

// // 检测掉线并恢复私钥
// List<DO> availableDOs = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// if (!missingDOIds.contains(i)) {
// availableDOs.add(doList.get(i));
// }
// }
// Map<Integer, BigInteger> recoveredKeys =
// csp.recoverMissingPrivateKeys(missingDOIds, availableDOs);

// // 验证恢复的私钥
// for (int missingDOId : missingDOIds) {
// BigInteger recoveredKey = recoveredKeys.get(missingDOId);
// System.out.println("恢复的 DO" + missingDOId + " 私钥: " + recoveredKey);
// System.out.println("与原始私钥一致: " +
// recoveredKey.equals(ta.doPrivateKeys.get(missingDOId))); // 验证一致性
// }

// // 模拟掉线 DO 的密文为加密的全 0 数据
// for (int missingDOId : missingDOIds) {
// // 创建全0模型参数数组
// BigInteger[] zeroCiphertext = new BigInteger[5];
// for (int i = 0; i < 5; i++) {
// zeroCiphertext[i] = csp.encryptZeroData(recoveredKeys.get(missingDOId),
// ta.getN(), ta.getG(),
// ta.getH());
// }
// csp.receiveData(missingDOId, zeroCiphertext);
// }

// // 计算和上报投影结果
// for (DO doObj : availableDOs) {
// doObj.calculateProjections();
// csp.receiveProjections(doObj.getId(), doObj.getProjectionResults());
// }

// // 聚合所有密文并解密
// BigInteger[] aggregated = csp.aggregate(ta.getN());
// List<BigInteger> allPrivateKeys = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// if (missingDOIds.contains(i)) {
// allPrivateKeys.add(recoveredKeys.get(i)); // 使用恢复的私钥
// } else {
// allPrivateKeys.add(ta.doPrivateKeys.get(i)); // 使用原始私钥
// }
// }
// double[] decryptedParams = csp.decrypt(aggregated, ta.getLambda(), ta.getN(),
// ta.getU(), ta.y);

// // 在解密后进行投毒检测
// List<Integer> suspectedDOs = csp.detectPoisoning(decryptedParams);

// if (!suspectedDOs.isEmpty()) {
// System.out.println("检测到可能的投毒行为，可疑的DO: " + suspectedDOs);
// } else {
// System.out.println("未检测到投毒行为");
// }

// // 计算在线DO数量（总数减去掉线数量）
// int activeCount = numDO - missingDOIds.size();
// double[] averagedParams = csp.calculateAverage(decryptedParams, activeCount);

// System.out.println("解密后的聚合模型参数: " + Arrays.toString(decryptedParams));
// System.out.println("平均后的全局模型参数: " + Arrays.toString(averagedParams));
// }

// private static void runConsistentPoisonTest(int numDO, BigInteger[]
// modelParamHashes) {
// TA ta = new TA(numDO, modelParamHashes);
// System.out.println("\nTA生成的正交向量组:");
// printOrthogonalVectors(ta.getOrthogonalVectors());

// List<DO> doList = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// doList.add(new DO(i, ta));
// }

// CSP csp = new CSP(ta, numDO);

// // 第一轮：上传加密的模型参数
// System.out.println("\n===== 第一轮：上传加密的模型参数 =====");
// for (int i = 0; i < numDO; i++) {
// DO doObj = doList.get(i);
// doObj.trainModel();

// // DO 3进行一致性投毒
// if (i == 3) {
// try {
// java.lang.reflect.Field field =
// DO.class.getDeclaredField("localModelParams");
// field.setAccessible(true);
// double[] params = (double[]) field.get(doObj);
// // 将参数方向反转并放大，作为投毒参数
// for (int j = 0; j < params.length; j++) {
// params[j] = -params[j] * 5; // 放大5倍并反转方向
// }
// // 保存修改后的参数到DO对象中
// field.set(doObj, params);
// System.out.println("DO 3 投毒后的参数: " + Arrays.toString(params));
// } catch (Exception e) {
// e.printStackTrace();
// }
// }

// // 使用安全加密机制加密参数
// doObj.encryptData(ta.getN(), ta.getG(), ta.getH());
// csp.receiveData(i, doObj.getEncryptedModelParams());
// }

// // 第二轮：直接使用相同参数计算投影结果，不再修改参数
// System.out.println("\n===== 第二轮：计算投影结果 =====");
// for (int i = 0; i < numDO; i++) {
// DO doObj = doList.get(i);
// // 直接计算投影，使用已有的参数（包括DO 3的投毒参数）
// doObj.calculateProjections();
// csp.receiveProjections(doObj.getId(), doObj.getProjectionResults());
// }

// // 执行聚合和检测
// runDetection(csp, ta, numDO, "一致性投毒");
// }

// private static void runDisguisedPoisonTest(int numDO, BigInteger[]
// modelParamHashes) {
// TA ta = new TA(numDO, modelParamHashes);
// System.out.println("\nTA生成的正交向量组:");
// printOrthogonalVectors(ta.getOrthogonalVectors());

// List<DO> doList = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// doList.add(new DO(i, ta));
// }

// CSP csp = new CSP(ta, numDO);

// // 保存正常DO的参数用于后续伪装
// Map<Integer, double[]> normalParams = new HashMap<>();

// // 第一轮：上传加密的模型参数
// System.out.println("\n===== 第一轮：上传加密的模型参数 =====");
// for (int i = 0; i < numDO; i++) {
// DO doObj = doList.get(i);
// doObj.trainModel();

// if (i == 3) {
// try {
// java.lang.reflect.Field field =
// DO.class.getDeclaredField("localModelParams");
// field.setAccessible(true);
// double[] params = (double[]) field.get(doObj);
// // 存储原参数用于后续伪装
// normalParams.put(i, Arrays.copyOf(params, params.length));
// // 进行投毒
// for (int j = 0; j < params.length; j++) {
// params[j] = -params[j] * 2;
// }
// field.set(doObj, params);
// System.out.println("DO 3 投毒参数: " + Arrays.toString(params));
// } catch (Exception e) {
// e.printStackTrace();
// }
// } else {
// // 保存正常DO的参数
// normalParams.put(i, Arrays.copyOf(doObj.getLocalModelParams(), 5));
// }

// // 使用安全加密机制加密参数
// doObj.encryptData(ta.getN(), ta.getG(), ta.getH());
// csp.receiveData(i, doObj.getEncryptedModelParams());
// }

// // 第二轮：DO 3使用伪装参数计算投影
// System.out.println("\n===== 第二轮：计算投影结果（DO 3伪装） =====");
// for (int i = 0; i < numDO; i++) {
// DO doObj = doList.get(i);

// if (i == 3) {
// try {
// java.lang.reflect.Field field =
// DO.class.getDeclaredField("localModelParams");
// field.setAccessible(true);
// // 使用正常DO的参数方向
// double[] fakeParams = new double[5];
// for (int j = 0; j < fakeParams.length; j++) {
// fakeParams[j] = normalParams.get((i + 1) % numDO)[j] * 0.9;
// }
// field.set(doObj, fakeParams);
// System.out.println("DO 3 伪装参数: " + Arrays.toString(fakeParams));
// } catch (Exception e) {
// e.printStackTrace();
// }
// }

// doObj.calculateProjections();
// csp.receiveProjections(doObj.getId(), doObj.getProjectionResults());
// }

// // 执行聚合和检测
// runDetection(csp, ta, numDO, "伪装投毒");
// }

// private static void runDetection(CSP csp, TA ta, int numDO, String testType)
// {
// // 第一轮：聚合和解密加密的模型参数
// BigInteger[] aggregated = csp.aggregate(ta.getN());
// List<BigInteger> allPrivateKeys = new ArrayList<>();
// for (int i = 0; i < numDO; i++) {
// allPrivateKeys.add(ta.doPrivateKeys.get(i));
// }

// double[] decryptedParams = csp.decrypt(aggregated, ta.getLambda(), ta.getN(),
// ta.getU(), ta.y);
// System.out.println("\n第一轮解密后的聚合模型参数M: " + Arrays.toString(decryptedParams));
// System.out.println(ta.y);

// // 直接进行投毒检测
// System.out.println("\n===== 投毒检测结果 =====");
// List<Integer> suspectedDOs = csp.detectPoisoning(decryptedParams);

// // 输出检测结果
// if (!suspectedDOs.isEmpty()) {
// System.out.println("检测到可疑DO: " + suspectedDOs);
// System.out.println("CSP通过比较点积结果发现参数不一致，并通过聚类分析找出了可疑DO");
// } else {
// System.out.println("未检测到异常行为，所有DO的点积结果一致");
// }
// }

// private static void printOrthogonalVectors(double[][] vectors) {
// for (int i = 0; i < vectors.length; i++) {
// System.out.println("向量" + i + ": " + Arrays.toString(vectors[i]));
// }
// }
// }