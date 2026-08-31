package dev.marcinromanowski.warden.core;

import dev.marcinromanowski.warden.api.SandboxEstablishmentException;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;

final class BwrapSessionStore {

  static final Path SESSIONS_DIRECTORY = Path.of("/var/lib/warden/sessions");

  private static final String LOCK_FILE_SUFFIX = ".lock";
  private static final String SESSION_SUBDIRECTORY = "session";
  private static final String TOOLS_SUBDIRECTORY = "tools";
  private static final Object SWEEP_MONITOR = new Object();
  private static final Set<Path> LOCKED_BY_THIS_JVM = ConcurrentHashMap.newKeySet();
  private static boolean swept;

  private BwrapSessionStore() {
  }

  static Session open(String sessionId, Consumer<String> diagnostics) {
    sweepOnce(diagnostics);
    Path root = SESSIONS_DIRECTORY.resolve(sessionId);
    HeldLock lock = acquireLock(root);
    try {
      Files.createDirectory(root);
      Files.createDirectory(root.resolve(SESSION_SUBDIRECTORY));
      Files.createDirectory(root.resolve(TOOLS_SUBDIRECTORY));
      return new Session(root, lock);
    } catch (IOException | RuntimeException e) {
      // The directory is this call's own to remove: nothing else can be holding it, because holding
      // it means holding the lock this call took before there was a directory at all.
      SandboxSessionDirectories.deleteQuietly(root);
      lock.close();
      throw new SandboxEstablishmentException("Failed to create sandbox session directory " + root, e);
    }
  }

  static void abandon(Session session) {
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
    Optional<HeldLock> held;
    try {
      held = lockFor(root);
    } catch (IOException e) {
      diagnostics.accept("could not lock abandoned sandbox session " + root.getFileName() + ": " + e);
      return;
    }
    if (held.isEmpty()) {
      return;
    }
    Session session = new Session(root, held.get());
    try {
      session.close();
      diagnostics.accept("reclaimed abandoned sandbox session " + root.getFileName());
    } catch (RuntimeException e) {
      session.lock()
          .close();
      diagnostics.accept("could not reclaim abandoned sandbox session " + root.getFileName() + ": " + e);
    }
  }

  private static HeldLock acquireLock(Path root) {
    try {
      return lockFor(root)
          .orElseThrow(() -> new IOException("session " + root.getFileName() + " is already locked"));
    } catch (IOException e) {
      throw new SandboxEstablishmentException("Failed to lock sandbox session " + root.getFileName(), e);
    }
  }

  private static Optional<HeldLock> lockFor(Path root) throws IOException {
    if (!LOCKED_BY_THIS_JVM.add(root)) {
      return Optional.empty();
    }
    FileChannel channel;
    try {
      channel = FileChannel.open(lockFile(root), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    } catch (IOException | RuntimeException e) {
      LOCKED_BY_THIS_JVM.remove(root);
      throw e;
    }
    try {
      FileLock lock = channel.tryLock();
      if (lock == null) {
        channel.close();
        LOCKED_BY_THIS_JVM.remove(root);
        return Optional.empty();
      }
      return Optional.of(new HeldLock(root, channel, lock));
    } catch (IOException | RuntimeException e) {
      closeQuietly(channel);
      LOCKED_BY_THIS_JVM.remove(root);
      throw e;
    }
  }

  private static Path lockFile(Path root) {
    return root.resolveSibling(root.getFileName() + LOCK_FILE_SUFFIX);
  }

  private static void closeQuietly(FileChannel channel) {
    if (channel == null) {
      return;
    }
    try {
      channel.close();
    } catch (IOException _) {
      // The lock is released either way, and there is nothing left to do with the channel.
    }
  }

  record Session(Path root, HeldLock lock) implements AutoCloseable {

    Path sessionDirectory() {
      return root.resolve(SESSION_SUBDIRECTORY);
    }

    Path toolsDirectory() {
      return root.resolve(TOOLS_SUBDIRECTORY);
    }

    @Override
    public void close() {
      AppArmorSessionPolicy.unload(root.getFileName()
          .toString());
      SandboxSessionDirectories.deleteQuietly(root);
      lock.close();
    }
  }

  record HeldLock(Path root, FileChannel channel, FileLock lock) implements AutoCloseable {

    @Override
    public void close() {
      try {
        Files.deleteIfExists(lockFile(root));
      } catch (IOException _) {
        // The lock still has to be released, and the next session with this id has a name of its own.
      }
      try {
        lock.release();
      } catch (IOException _) {
        // Closing the channel below releases it regardless.
      }
      closeQuietly(channel);
      LOCKED_BY_THIS_JVM.remove(root);
    }
  }
}
