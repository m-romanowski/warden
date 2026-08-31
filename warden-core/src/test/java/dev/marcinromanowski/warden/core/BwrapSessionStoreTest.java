package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

@EnabledOnOs(OS.LINUX)
class BwrapSessionStoreTest {

  private static final int OTHER_WRITE_MODE_BIT = 0b000_000_010;
  private static final Duration CONCURRENT_SWEEP_DURATION = Duration.ofSeconds(3);
  private static final int MINIMUM_SESSIONS_OPENED = 20;

  @Test
  void keepsASessionSomewhereNoOtherLocalUserCanWrite() throws IOException {
    String sessionId = newSessionId();

    try (BwrapSessionStore.Session session = BwrapSessionStore.open(sessionId, _ -> { })) {
      assertThat(modeOf(BwrapSessionStore.SESSIONS_DIRECTORY) & OTHER_WRITE_MODE_BIT)
          .as("the directory holding every session's bwrap copy must not be world-writable, which"
              + " is exactly what java.io.tmpdir is")
          .isZero();
      assertThat(session.toolsDirectory())
          .as("the bwrap copy warden's confinement profile attaches to lives here")
          .isDirectory();
      assertThat(Files.getPosixFilePermissions(session.root()))
          .doesNotContain(PosixFilePermission.OTHERS_WRITE);
    }
  }

  @Test
  void removesTheSessionPolicyOnCloseEvenWhenNothingEverHeldAHandleToIt() throws IOException {
    String sessionId = newSessionId();
    BwrapSessionStore.Session session = BwrapSessionStore.open(sessionId, _ -> { });
    TestProcesses.run(helperCommand("load", sessionId), "  /** r,\n");
    assertThat(loadedProfileNames())
        .as("the policy has to reach the kernel for this to be testing anything")
        .contains("warden-sandbox-" + sessionId);

    session.close();

    assertThat(loadedProfileNames())
        .doesNotContain("warden-sandbox-" + sessionId);
    assertThat(session.root())
        .doesNotExist();
  }

  @Test
  void closesASessionWhosePolicyNeverReachedTheKernel() {
    String sessionId = newSessionId();
    BwrapSessionStore.Session session = BwrapSessionStore.open(sessionId, _ -> { });

    session.close();

    assertThat(session.root())
        .as("every teardown path closes a session, including the ones that failed before a load, so"
            + " removing a policy that is already absent has to succeed")
        .doesNotExist();
  }

  @Test
  void reclaimsTheProfilesAndFilesOfASessionNoOneIsHoldingAnyMore() throws IOException {
    String abandoned = newSessionId();
    stageSession(abandoned);
    TestProcesses.run(helperCommand("load", abandoned), "  /** r,\n");
    assertThat(loadedProfileNames())
        .as("the abandoned session's profiles have to be loaded for this to be testing anything")
        .contains("warden-sandbox-" + abandoned);

    BwrapSessionStore.sweep(_ -> { });

    assertThat(loadedProfileNames())
        .as("a profile whose session is gone stays loaded until the machine reboots, and its"
            + " attachment path is a userns grant to whoever recreates it")
        .doesNotContain("warden-sandbox-" + abandoned);
    assertThat(BwrapSessionStore.SESSIONS_DIRECTORY.resolve(abandoned))
        .doesNotExist();
  }

  @Test
  void leavesASessionAnotherProcessIsStillHolding() throws IOException, InterruptedException {
    String held = newSessionId();
    Path root = stageSession(held);
    Process holder = holdLockUntilKilled(lockFileOf(held));

    try {
      assertThat(holder.waitFor(2, TimeUnit.SECONDS))
          .as("the holder must stay alive while the sweep runs")
          .isFalse();

      BwrapSessionStore.sweep(_ -> { });

      assertThat(root)
          .as("a sweep that cannot tell a live session from an abandoned one deletes the files of"
              + " every session another JVM on this machine has open")
          .exists();
    } finally {
      holder.destroyForcibly();
      SandboxSessionDirectories.deleteQuietly(root);
      Files.deleteIfExists(lockFileOf(held));
    }
  }

  @Test
  void keepsEverySessionAConcurrentSweepFromAnotherProcessRunsAlongside()
      throws IOException, InterruptedException {
    Process sweeper = sweepAbandonedSessionsUntilKilled();

    try {
      long deadline = System.nanoTime() + CONCURRENT_SWEEP_DURATION.toNanos();
      int opened = 0;
      while (System.nanoTime() < deadline) {
        String sessionId = newSessionId();
        try (BwrapSessionStore.Session session = BwrapSessionStore.open(sessionId, _ -> { })) {
          assertThat(session.sessionDirectory())
              .as("a sweep running in another process must not take a live session's files away")
              .isDirectory();
          opened++;
        }
      }
      assertThat(opened)
          .as("the loop has to actually open sessions for this to be testing anything")
          .isGreaterThan(MINIMUM_SESSIONS_OPENED);
    } finally {
      sweeper.destroyForcibly();
      sweeper.waitFor();
      deleteLockFilesWithNoSessionBesideThem();
    }
  }

  private static Process sweepAbandonedSessionsUntilKilled() throws IOException {
    return new ProcessBuilder(
        List.of(
            "python3", "-c",
            "import fcntl,os,re,shutil,sys\n"
                + "sessions=sys.argv[1]\n"
                + "while True:\n"
                + "  for name in os.listdir(sessions):\n"
                + "    if not re.fullmatch('[0-9a-f]{32}', name): continue\n"
                + "    try:\n"
                + "      f=open(os.path.join(sessions, name + '.lock'),'w')\n"
                + "      fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\n"
                + "    except OSError:\n"
                + "      continue\n"
                + "    shutil.rmtree(os.path.join(sessions, name), ignore_errors=True)\n"
                + "    os.unlink(f.name)\n"
                + "    f.close()\n",
            BwrapSessionStore.SESSIONS_DIRECTORY.toString()
        )
    )
        .redirectErrorStream(true)
        .start();
  }

  private static void deleteLockFilesWithNoSessionBesideThem() throws IOException {
    try (Stream<Path> entries = Files.list(BwrapSessionStore.SESSIONS_DIRECTORY)) {
      for (Path entry : entries.toList()) {
        String name = entry.getFileName()
            .toString();
        if (name.endsWith(".lock") && !Files.exists(entry.resolveSibling(name.replace(".lock", "")))) {
          Files.deleteIfExists(entry);
        }
      }
    }
  }

  private static Process holdLockUntilKilled(Path lockPath) throws IOException {
    return new ProcessBuilder(
        List.of(
            "python3", "-c",
            "import fcntl,sys,time\n"
                + "f=open(sys.argv[1],'w')\n"
                + "fcntl.lockf(f, fcntl.LOCK_EX)\n"
                + "time.sleep(600)\n",
            lockPath.toString()
        )
    )
        .redirectErrorStream(true)
        .start();
  }

  private static Path lockFileOf(String sessionId) {
    return BwrapSessionStore.SESSIONS_DIRECTORY.resolve(sessionId + ".lock");
  }

  private static Path stageSession(String sessionId) throws IOException {
    Path root = BwrapSessionStore.SESSIONS_DIRECTORY.resolve(sessionId);
    Files.createDirectories(root.resolve("session"));
    Files.createDirectories(root.resolve("tools"));
    return root;
  }

  private static String newSessionId() {
    return UUID.randomUUID()
        .toString()
        .replace("-", "");
  }

  private static List<String> helperCommand(String action, String sessionId) {
    return List.of("sudo", AppArmorSessionPolicy.POLICY_HELPER.toString(), action, sessionId);
  }

  private static Set<String> loadedProfileNames() throws IOException {
    return AaStatusProfiles.parse(TestProcesses.run(List.of("sudo", "aa-status", "--json"))
            .output())
        .keySet();
  }

  private static int modeOf(Path path) throws IOException {
    return (int) Files.getAttribute(path, "unix:mode");
  }
}
