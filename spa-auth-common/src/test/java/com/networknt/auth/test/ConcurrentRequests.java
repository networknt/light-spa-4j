package com.networknt.auth.test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Dedicated blocking request threads; leave HttpClient's completion pool available. */
public final class ConcurrentRequests {
    private ConcurrentRequests() { }

    public static <T> List<T> run(int count, Callable<T> request) throws Exception {
        return run(count, request, Duration.ofSeconds(10));
    }

    static <T> List<T> run(int count, Callable<T> request, Duration timeout) throws Exception {
        var executor = Executors.newFixedThreadPool(count,
                Thread.ofPlatform().daemon(true).name("concurrent-request-", 0).factory());
        var requests = new ArrayList<Future<T>>();
        try {
            var ready = new CountDownLatch(count);
            var start = new CountDownLatch(1);
            for (int i = 0; i < count; i++) requests.add(executor.submit(() -> {
                ready.countDown();
                if (!start.await(5, TimeUnit.SECONDS)) throw new TimeoutException("concurrent start timed out");
                return request.call();
            }));
            try {
                if (!ready.await(5, TimeUnit.SECONDS)) throw new TimeoutException("request workers did not start");
            } finally {
                start.countDown();
            }
            var responses = new ArrayList<T>();
            long deadline = System.nanoTime() + timeout.toNanos();
            for (var future : requests) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new TimeoutException("concurrent requests timed out");
                responses.add(future.get(remaining, TimeUnit.NANOSECONDS));
            }
            return responses;
        } finally {
            for (var future : requests) future.cancel(true);
            executor.shutdownNow();
            // A transport may ignore interruption. Never use ExecutorService.close(),
            // which could turn the request timeout into an unbounded shutdown wait.
            executor.awaitTermination(100, TimeUnit.MILLISECONDS);
        }
    }
}
