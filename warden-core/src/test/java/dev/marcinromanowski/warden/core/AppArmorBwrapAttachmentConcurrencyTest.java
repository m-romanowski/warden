package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

// AppArmorBwrapAttachment's read-modify-write-reload sequence against the shared, root-owned
// /etc/apparmor.d/local/bwrap-userns-restrict file runs as a single flock-guarded privileged
// script specifically so concurrent sessions can't corrupt each other's px stacking line - this
// test proves that property against real concurrent attach()/close() calls, not just by reasoning
// that "grep -v -F scoped by a unique path should keep them independent." Real system state:
// writes to the actual override file on whatever machine runs this, cleaned up in a finally block
// regardless of outcome so a failure never leaves a stray line behind. Requires passwordless
// sudo for apparmor_parser, same convention as the sibling enforcement tests.
@EnabledOnOs(OS.LINUX)
class AppArmorBwrapAttachmentConcurrencyTest {

  private static final Path OVERRIDE_FILE = Path.of("/etc/apparmor.d/local/bwrap-userns-restrict");
  private static final int SESSION_COUNT = 6;

  @Test
  void concurrentSessionsEachGetAnIndependentLineAndEachCloseOnlyRemovesItsOwn(@TempDir Path tempDir)
      throws Exception {
    List<Path> targets = IntStream.range(0, SESSION_COUNT)
        .mapToObj(index -> tempDir.resolve("target-" + index + "-" + UUID.randomUUID()))
        .toList();
    List<String> profileNames = IntStream.range(0, SESSION_COUNT)
        .mapToObj(index -> "warden-concurrency-test-" + index + "-" + UUID.randomUUID()
            .toString()
            .replace("-", ""))
        .toList();

    List<AppArmorBwrapAttachment> attachments = attachAllConcurrently(targets, profileNames);
    try {
      String afterAttach = Files.readString(OVERRIDE_FILE);
      for (int index = 0; index < SESSION_COUNT; index++) {
        assertThat(afterAttach)
            .as("session %d's own px line must be present after concurrent attach", index)
            .contains(stackingLineFragment(targets.get(index), profileNames.get(index)));
      }

      List<AppArmorBwrapAttachment> closedNow = attachments.subList(0, SESSION_COUNT / 2);
      closeAllConcurrently(closedNow);

      String afterPartialClose = Files.readString(OVERRIDE_FILE);
      for (int index = 0; index < SESSION_COUNT / 2; index++) {
        assertThat(afterPartialClose)
            .as("a closed session's own px line must be removed, not left behind")
            .doesNotContain(stackingLineFragment(targets.get(index), profileNames.get(index)));
      }
      for (int index = SESSION_COUNT / 2; index < SESSION_COUNT; index++) {
        assertThat(afterPartialClose)
            .as("closing one session must not remove a still-open sibling session's own line")
            .contains(stackingLineFragment(targets.get(index), profileNames.get(index)));
      }

      List<AppArmorBwrapAttachment> stillOpen = attachments.subList(SESSION_COUNT / 2, SESSION_COUNT);
      closeAllConcurrently(stillOpen);
      attachments = List.of();
    } finally {
      // Best-effort cleanup of anything not already closed above (e.g. if an assertion failed
      // partway through) - a real shared system file must never be left polluted by a failed run.
      for (AppArmorBwrapAttachment attachment : attachments) {
        attachment.close();
      }
    }
  }

  private static List<AppArmorBwrapAttachment> attachAllConcurrently(List<Path> targets, List<String> profileNames)
      throws InterruptedException {
    try (ExecutorService pool = Executors.newFixedThreadPool(SESSION_COUNT)) {
      CountDownLatch startLatch = new CountDownLatch(1);
      List<Future<AppArmorBwrapAttachment>> futures = new ArrayList<>();
      for (int index = 0; index < SESSION_COUNT; index++) {
        Path target = targets.get(index);
        String profileName = profileNames.get(index);
        futures.add(pool.submit(() -> {
          startLatch.await();
          return AppArmorBwrapAttachment.attach(target, profileName);
        }));
      }
      startLatch.countDown();
      return awaitAllClosingSuccessfulOnesIfAnyFail(futures);
    }
  }

  // If one attach() among the batch fails, any that already succeeded must still be detached -
  // otherwise a mid-batch failure would leak their px lines in the real shared system file forever.
  private static List<AppArmorBwrapAttachment> awaitAllClosingSuccessfulOnesIfAnyFail(
      List<Future<AppArmorBwrapAttachment>> futures
  ) throws InterruptedException {
    List<AppArmorBwrapAttachment> succeeded = new ArrayList<>();
    Throwable firstFailure = null;
    for (Future<AppArmorBwrapAttachment> future : futures) {
      try {
        succeeded.add(future.get());
      } catch (java.util.concurrent.ExecutionException e) {
        firstFailure = firstFailure == null ? e.getCause() : firstFailure;
      }
    }
    if (firstFailure != null) {
      for (AppArmorBwrapAttachment attachment : succeeded) {
        attachment.close();
      }
      throw new AssertionError("Concurrent AppArmorBwrapAttachment.attach() failed", firstFailure);
    }
    return succeeded;
  }

  private static void closeAllConcurrently(List<AppArmorBwrapAttachment> attachments) throws InterruptedException {
    try (ExecutorService pool = Executors.newFixedThreadPool(Math.max(1, attachments.size()))) {
      CountDownLatch startLatch = new CountDownLatch(1);
      List<Future<Void>> futures = new ArrayList<>();
      for (AppArmorBwrapAttachment attachment : attachments) {
        futures.add(pool.submit(() -> {
          startLatch.await();
          attachment.close();
          return null;
        }));
      }
      startLatch.countDown();
      awaitAll(futures);
    }
  }

  private static <T> void awaitAll(List<Future<T>> futures) throws InterruptedException {
    for (Future<T> future : futures) {
      try {
        future.get();
      } catch (java.util.concurrent.ExecutionException e) {
        throw new AssertionError("Concurrent AppArmorBwrapAttachment call failed", e.getCause());
      }
    }
  }

  private static String stackingLineFragment(Path target, String profileName) {
    return "px " + target + " -> bwrap//&unpriv_bwrap//&" + profileName + ",";
  }
}
