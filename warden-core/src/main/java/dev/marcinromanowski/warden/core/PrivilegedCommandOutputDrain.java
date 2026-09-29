package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;

record PrivilegedCommandOutputDrain(Thread thread, AtomicReference<String> captured) {

  static PrivilegedCommandOutputDrain start(Process process) {
    AtomicReference<String> captured = new AtomicReference<>("");
    Thread thread = new Thread(
        () -> {
          try {
            captured.set(
                new String(
                    process.getInputStream()
                        .readAllBytes(),
                    StandardCharsets.UTF_8
                )
            );
          } catch (IOException e) {
            captured.set("(privileged command output unreadable: " + e.getMessage() + ")");
          }
        },
        "warden-privileged-output"
    );
    thread.setDaemon(true);
    thread.start();
    return new PrivilegedCommandOutputDrain(thread, captured);
  }

  String await(Duration timeout) {
    try {
      thread.join(timeout.toMillis());
    } catch (InterruptedException e) {
      Thread.currentThread()
          .interrupt();
    }
    return captured.get();
  }

}
