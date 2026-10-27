package com.networknt.auth.test;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class ConcurrentRequestsTest {
    @Test
    void interruptIgnoringRequestDoesNotBlockTimeoutCleanup() {
        var release = new CountDownLatch(1);
        try {
            assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                assertThrows(TimeoutException.class, () -> ConcurrentRequests.run(1, () -> {
                    while (release.getCount() != 0) {
                        try {
                            release.await();
                        } catch (InterruptedException ignored) {
                            // Model a stuck transport that does not honor cancellation.
                        }
                    }
                    return "released";
                }, Duration.ofMillis(50))));
        } finally {
            release.countDown();
        }
    }
}
