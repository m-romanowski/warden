package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;

final class BwrapSessionStore {

  static final Path SESSIONS_DIRECTORY = Path.of("/var/lib/warden/sessions");

  private static final Object SWEEP_MONITOR = new Object();
  private static boolean swept;

  private BwrapSessionStore() {
  }

  static BwrapSession open(String sessionId, Consumer<String> diagnostics) {
    sweepOnce(diagnostics);
    Path root = SESSIONS_DIRECTORY.resolve(sessionId);
    BwrapSessionLock lock = acquireLock(root);
    BwrapSession session = new BwrapSession(root, lock);
    try {
      Files.createDirectory(root);
      Files.createDirectory(session.sessionDirectory());
      Files.createDirectory(session.toolsDirectory());
      return session;
    } catch (IOException | RuntimeException e) {
      // The directory is this call's own to remove: nothing else can be holding it, because holding
      // it means holding the lock this call took before there was a directory at all.
      SandboxSessionDirectories.deleteQuietly(root);
      lock.close();
      throw new SandboxEstablishmentException("Failed to create sandbox session directory " + root, e);
    }
  }

  static void abandon(BwrapSession session) {
    session.lock()
        .close();
  }

  private static void sweepOnce(Consumer<String> diagnostics) {
    synchronized (SWEEP_MONITOR) {
      if (swept) {
        return;
      }
      swept = true;
      sweep(diagnostics);
    }
  }

  static void sweep(Consumer<String> diagnostics) {
    if (!Files.isDirectory(SESSIONS_DIRECTORY)) {
      return;
    }
    try (Stream<Path> entries = Files.list(SESSIONS_DIRECTORY)) {
      entries.filter(entry -> AppArmorSessionProfileNames.isSessionId(entry.getFileName()
              .toString()))
          .toList()
          .forEach(entry -> reclaim(entry, diagnostics));
    } catch (IOException e) {
      diagnostics.accept("could not sweep abandoned sandbox sessions: " + e);
    }
  }

  private static void reclaim(Path root, Consumer<String> diagnostics) {
    Optional<BwrapSessionLock> held;
    try {
      held = BwrapSessionLock.tryAcquire(root);
    } catch (IOException e) {
      diagnostics.accept("could not lock abandoned sandbox session " + root.getFileName() + ": " + e);
      return;
    }
    if (held.isEmpty()) {
      return;
    }
    BwrapSession session = new BwrapSession(root, held.get());
    try {
      session.close();
      diagnostics.accept("reclaimed abandoned sandbox session " + root.getFileName());
    } catch (RuntimeException e) {
      session.lock()
          .close();
      diagnostics.accept("could not reclaim abandoned sandbox session " + root.getFileName() + ": " + e);
    }
  }

  private static BwrapSessionLock acquireLock(Path root) {
    try {
      return BwrapSessionLock.tryAcquire(root)
          .orElseThrow(() -> new IOException("session " + root.getFileName() + " is already locked"));
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to lock sandbox session " + root.getFileName(), e);
    }
  }
}
