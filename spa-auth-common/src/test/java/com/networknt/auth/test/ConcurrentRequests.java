package com.networknt.auth.test;

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
        try (var executor = Executors.newFixedThreadPool(count)) {
            var ready = new CountDownLatch(count);
            var start = new CountDownLatch(1);
            var requests = new ArrayList<Future<T>>();
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
            for (var future : requests) responses.add(future.get(10, TimeUnit.SECONDS));
            return responses;
        }
    }
}
