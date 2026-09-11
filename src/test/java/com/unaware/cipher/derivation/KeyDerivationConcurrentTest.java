package com.unaware.cipher.derivation;
import com.unaware.cipher.UnawareCipherSuite;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
/**
 * 多线程批量压测 KeyDerivation 类
 *
 * @author: Roy rui wang
 * @data 2026年02月06日 12:43
 */
public class KeyDerivationConcurrentTest {
    private static final String TEST_SUBJECT_DOMAIN = "test-business-module";
    private static final int TEST_KEY_VERSION = 1;
    private static final int THREAD_COUNT = 10;  // 并发线程数
    private static final int TOTAL_OPERATIONS = 1000;  // 总操作次数
    private static final String LOAD_KEYSTORE_PATH = "jks/yunwuye-bizSys-other.jks";
    private static final String TEST_KEYSTORE_PASSWORD = "yunwuyeBizSysOther2024123!@#";
    private static final String TEST_ROOT_KEY_PASSWORD = "yunwuyeRootKey2024123!@#";

    private static final long TASK_TIMEOUT_SECONDS = 30;  // 单个任务超时时间（秒）

    private UnawareCipherSuite yunwuyeCipherSuite;

    /**
     * 测试多线程并发派生密钥
     */
    @Test
    public void testConcurrentDeriveKey() throws Exception {
        // 创建共享的根密钥
//        byte[] seed = new byte[32];
//        new SecureRandom().nextBytes(seed);
//        final SecretKey rootKey = KeyDerivation.createRootKey(seed);


        String path = Objects.requireNonNull(this.getClass().getClassLoader().getResource(LOAD_KEYSTORE_PATH)).getFile();
        yunwuyeCipherSuite = UnawareCipherSuite.loadExisting(path, TEST_KEYSTORE_PASSWORD);
        SecretKey rootKey = yunwuyeCipherSuite.getDefaultRootKey(TEST_ROOT_KEY_PASSWORD);
        System.out.println("--------------获取根密钥:"+ UnawareCipherSuite.getSecretKeyStr(rootKey));

        // 创建线程池
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_COUNT);

        // 记录开始时间
        long startTime = System.currentTimeMillis();

        // 创建任务列表
        List<Callable<TestResult>> tasks = new ArrayList<>();
        int operationsPerThread = TOTAL_OPERATIONS / THREAD_COUNT;

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int threadId = i;
            tasks.add(() -> performDerivationOperations(rootKey, operationsPerThread, threadId));
        }

        // 执行所有任务并收集结果
        List<Future<TestResult>> futures = executorService.invokeAll(tasks);

        // 统计结果 - 改进版，添加超时处理
        int successCount = 0;
        int failureCount = 0;
        List<String> errors = new ArrayList<>();
        int timeoutTasks = 0;

        for (int i = 0; i < futures.size(); i++) {
            Future<TestResult> future = futures.get(i);
            try {
                // 使用带超时的 get 方法，避免无限期等待
                TestResult result = future.get(TASK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                successCount += result.successCount;
                failureCount += result.failureCount;
                errors.addAll(result.errors);
            } catch (TimeoutException e) {
                // 处理超时情况
                timeoutTasks++;
                String errorMsg = "线程 " + i + " 的任务超时 (" + TASK_TIMEOUT_SECONDS + "秒)";
                errors.add(errorMsg);
                failureCount++;
                System.err.println(errorMsg);

                // 取消超时的任务
                future.cancel(true);
            } catch (ExecutionException e) {
                // 处理任务执行中的异常
                String errorMsg = "线程 " + i + " 的任务执行异常: " + e.getCause().getMessage();
                errors.add(errorMsg);
                failureCount++;
                System.err.println(errorMsg);
            }
        }

        // 关闭线程池
        executorService.shutdownNow(); // 使用 shutdownNow 确保强制关闭

        // 输出统计结果
        long endTime = System.currentTimeMillis();
        System.out.println("=== 多线程并发测试结果 ===");
        System.out.println("总操作数: " + TOTAL_OPERATIONS);
        System.out.println("成功操作数: " + successCount);
        System.out.println("失败操作数: " + failureCount);
        System.out.println("超时任务数: " + timeoutTasks);
        System.out.println("执行时间: " + (endTime - startTime) + "ms");
        System.out.println("吞吐量: " + (successCount + failureCount > 0 ?
                (double)(successCount + failureCount) * 1000.0 / (endTime - startTime) : 0) + " ops/s");

        if (!errors.isEmpty()) {
            System.out.println("错误详情:");
            errors.forEach(error -> System.out.println("  " + error));
        }

        // 验证测试结果
        assert failureCount <= timeoutTasks : "存在失败的操作: " + failureCount + ", 超时任务: " + timeoutTasks;
        assert successCount + timeoutTasks == TOTAL_OPERATIONS : "成功操作数不匹配";
    }

    /**
     * 在单个线程中执行指定数量的密钥派生操作
     */
    private TestResult performDerivationOperations(SecretKey rootKey, int operationCount, int threadId) {
        TestResult result = new TestResult();

        try {
            final int pwLength = 10;
            for (int i = 0; i < operationCount; i++) {
                try {
                    String input =TEST_SUBJECT_DOMAIN + "_" + threadId + "_" + i;
                    String derivedKey = KeyDerivation.derivePassword( rootKey, input, pwLength);
                    System.out.println("线程" + threadId + "第" + i + "次操作, 输入input: "+ input + "， 派生的密钥:"+derivedKey+"符合要求");
                    if (derivedKey != null &&  derivedKey.length() == pwLength) {
                        result.successCount++;
                    } else {
                        result.errors.add("线程" + threadId + "第" + i + "次操作: 派生的密钥不符合要求");
                        result.failureCount++;
                    }
                    // 派生密钥
//                    SecretKey derivedKey = KeyDerivation.deriveKey(rootKey,
//                            TEST_SUBJECT_DOMAIN + "_" + threadId + "_" + i,
//                            TEST_KEY_VERSION, 48
//                    );
//                    System.out.println("线程" + threadId + "第" + i + "次操作: 派生的密钥:"+ yunwuyeCipherSuite.getSecretKeyStr(derivedKey)+"符合要求");
//                    // 验证派生的密钥是否有效
//                    if (derivedKey != null && "AES".equals(derivedKey.getAlgorithm()) && derivedKey.getEncoded().length == 32) {
//                        result.successCount++;
//                    } else {
//                        result.errors.add("线程" + threadId + "第" + i + "次操作: 派生的密钥不符合要求");
//                        result.failureCount++;
//                    }
                } catch (Exception e) {
                    result.errors.add("线程" + threadId + "第" + i + "次操作异常: " + e.getMessage());
                    result.failureCount++;
                }
            }
        } catch (Exception e) {
            result.errors.add("线程" + threadId + "执行过程中发生异常: " + e.getMessage());
            result.failureCount++;
        }

        return result;
    }

    /**
     * 测试结果统计类
     */
    private static class TestResult {
        int successCount = 0;
        int failureCount = 0;
        List<String> errors = new ArrayList<>();
    }

    /**
     * 测试多线程同时创建根密钥
     */
    @Test
    public void testConcurrentCreateRootKey() throws Exception {
        // 创建线程池
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_COUNT);

        // 记录开始时间
        long startTime = System.currentTimeMillis();

        // 创建任务列表
        List<Callable<TestResult>> tasks = new ArrayList<>();
        int operationsPerThread = TOTAL_OPERATIONS / THREAD_COUNT;

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int threadId = i;
            tasks.add(() -> performRootKeyCreationOperations(operationsPerThread, threadId));
        }

        // 执行所有任务并收集结果
        List<Future<TestResult>> futures = executorService.invokeAll(tasks);

        // 统计结果
        int successCount = 0;
        int failureCount = 0;
        List<String> errors = new ArrayList<>();

        for (Future<TestResult> future : futures) {
            TestResult result = future.get();
            successCount += result.successCount;
            failureCount += result.failureCount;
            errors.addAll(result.errors);
        }

        // 关闭线程池
        executorService.shutdown();

        // 输出统计结果
        long endTime = System.currentTimeMillis();
        System.out.println("=== 多线程创建根密钥测试结果 ===");
        System.out.println("总操作数: " + TOTAL_OPERATIONS);
        System.out.println("成功操作数: " + successCount);
        System.out.println("失败操作数: " + failureCount);
        System.out.println("执行时间: " + (endTime - startTime) + "ms");
        System.out.println("吞吐量: " + (TOTAL_OPERATIONS * 1000.0 / (endTime - startTime)) + " ops/s");

        if (!errors.isEmpty()) {
            System.out.println("错误详情:");
            errors.forEach(error -> System.out.println("  " + error));
        }

        // 验证测试结果
        assert failureCount == 0 : "存在失败的操作: " + failureCount;
        assert successCount == TOTAL_OPERATIONS : "成功操作数不匹配";
    }

    /**
     * 在单个线程中执行指定数量的根密钥创建操作
     */
    private TestResult performRootKeyCreationOperations(int operationCount, int threadId) {
        TestResult result = new TestResult();
        SecureRandom secureRandom = new SecureRandom();

        try {
            for (int i = 0; i < operationCount; i++) {
                try {
                    // 生成随机种子
                    byte[] seed = new byte[32];
                    secureRandom.nextBytes(seed);

                    // 创建根密钥
                    SecretKey rootKey = KeyDerivation.createRootKey(seed);

                    // 验证创建的根密钥是否有效
                    if (rootKey != null &&
                            "AES".equals(rootKey.getAlgorithm()) &&
                            rootKey.getEncoded().length == 32) {
                        result.successCount++;
                    } else {
                        result.errors.add("线程" + threadId + "第" + i + "次操作: 创建的根密钥不符合要求");
                        result.failureCount++;
                    }
                } catch (Exception e) {
                    result.errors.add("线程" + threadId + "第" + i + "次操作异常: " + e.getMessage());
                    result.failureCount++;
                }
            }
        } catch (Exception e) {
            result.errors.add("线程" + threadId + "执行过程中发生异常: " + e.getMessage());
            result.failureCount++;
        }

        return result;
    }

    /**
     * 混合操作压力测试：同时进行根密钥创建和密钥派生
     */
    @Test
    public void testMixedConcurrentOperations() throws Exception {
        // 创建线程池
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_COUNT);

        // 记录开始时间
        long startTime = System.currentTimeMillis();

        // 创建混合任务列表：一半线程执行根密钥创建，一半执行密钥派生
        List<Callable<TestResult>> tasks = new ArrayList<>();
        int derivationThreads = THREAD_COUNT / 2;
        int creationThreads = THREAD_COUNT - derivationThreads;
        int operationsPerThread = TOTAL_OPERATIONS / THREAD_COUNT;

        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        final SecretKey rootKey = KeyDerivation.createRootKey(seed);
        // 添加密钥派生任务
        for (int i = 0; i < derivationThreads; i++) {
            int threadId = i;
            tasks.add(() -> performDerivationOperations(rootKey, operationsPerThread, threadId));
        }

        // 添加根密钥创建任务
        for (int i = 0; i < creationThreads; i++) {
            int threadId = i;
            tasks.add(() -> performRootKeyCreationOperations(operationsPerThread, threadId + derivationThreads));
        }

        // 执行所有任务并收集结果
        List<Future<TestResult>> futures = executorService.invokeAll(tasks);

        // 统计结果
        int successCount = 0;
        int failureCount = 0;
        List<String> errors = new ArrayList<>();

        for (Future<TestResult> future : futures) {
            TestResult result = future.get();
            successCount += result.successCount;
            failureCount += result.failureCount;
            errors.addAll(result.errors);
        }

        // 关闭线程池
        executorService.shutdown();

        // 输出统计结果
        long endTime = System.currentTimeMillis();
        System.out.println("=== 混合操作压力测试结果 ===");
        System.out.println("总操作数: " + TOTAL_OPERATIONS);
        System.out.println("成功操作数: " + successCount);
        System.out.println("失败操作数: " + failureCount);
        System.out.println("执行时间: " + (endTime - startTime) + "ms");
        System.out.println("吞吐量: " + (TOTAL_OPERATIONS * 1000.0 / (endTime - startTime)) + " ops/s");

        if (!errors.isEmpty()) {
            System.out.println("错误详情:");
            errors.forEach(error -> System.out.println("  " + error));
        }

        // 验证测试结果
        assert failureCount == 0 : "存在失败的操作: " + failureCount;
        assert successCount == TOTAL_OPERATIONS : "成功操作数不匹配";
    }
}
