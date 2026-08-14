package dev.marcinromanowski.warden.core;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

final class SandboxThreads {

  private SandboxThreads() {
  }

  static ScheduledExecutorService singleScheduledExecutor(String threadName) {
    return Executors.newSingleThreadScheduledExecutor(
        runnable -> namedDaemonThread(Preconditions.nonBlank(threadName, "threadName"), runnable)
    );
  }

  static Thread namedDaemonThread(String threadName, Runnable runnable) {
    Thread thread = Executors.defaultThreadFactory()
        .newThread(Preconditions.nonNull(runnable, "runnable"));
    thread.setName(Preconditions.nonBlank(threadName, "threadName"));
    thread.setDaemon(true);
    return thread;
  }
}
