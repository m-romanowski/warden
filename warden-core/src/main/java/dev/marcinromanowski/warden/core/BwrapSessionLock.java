package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

record BwrapSessionLock(
    Path root,
    FileChannel channel,
    FileLock lock
) implements AutoCloseable {

  private static final String LOCK_FILE_SUFFIX = ".lock";
  private static final Set<Path> LOCKED_BY_THIS_JVM = ConcurrentHashMap.newKeySet();

  static Optional<BwrapSessionLock> tryAcquire(Path root) throws IOException {
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
      return Optional.of(new BwrapSessionLock(root, channel, lock));
    } catch (IOException | RuntimeException e) {
      closeQuietly(channel);
      LOCKED_BY_THIS_JVM.remove(root);
      throw e;
    }
  }

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
}
