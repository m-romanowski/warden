package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

@EnabledOnOs(OS.LINUX)
class AppArmorPolicyHelperBoundTest {

  private static final String VENDOR_PROFILE = "/usr/bin/man";
  private static final String WELL_FORMED_BODY = "  #include <abstractions/base>\n  /** r,\n";

  @Test
  void loadsAndRemovesExactlyTheThreeProfilesTheSessionIdNames() throws IOException {
    String sessionId = newSessionId();

    SandboxExecResult loaded = helper("load", sessionId, WELL_FORMED_BODY);
    Map<String, String> whileLoaded = loadedProfiles();
    SandboxExecResult unloaded = helper("unload", sessionId, "");

    assertThat(loaded.exitCode())
        .as("positive control: a well-formed body must load: %s", loaded.output())
        .isZero();
    assertThat(whileLoaded)
        .as("the helper writes all three profile headers itself, from the session id alone")
        .containsKeys(
            "warden-bwrap-" + sessionId, "warden-unpriv-" + sessionId, "warden-sandbox-" + sessionId
        );
    assertThat(unloaded.exitCode())
        .as("removal takes the session id, so a session with no policy file left is still"
            + " removable: %s", unloaded.output())
        .isZero();
    assertThat(loadedProfiles())
        .doesNotContainKeys(
            "warden-bwrap-" + sessionId, "warden-unpriv-" + sessionId, "warden-sandbox-" + sessionId
        );
  }

  @Test
  void refusesTheBodyThatWouldDeclareItsOwnProfile() throws IOException {
    String sessionId = newSessionId();
    String escaping = "  /** r,\n}\nprofile " + VENDOR_PROFILE + " flags=(complain) {\n  /** rwmlkix,\n";

    SandboxExecResult refused = helper("load", sessionId, escaping);

    assertThat(refused.exitCode())
        .as("a brace in the body closes the block the helper opened, and the next one opens a"
            + " profile of the caller's choosing: %s", refused.output())
        .isNotZero();
    assertThat(loadedProfiles())
        .as("the distribution's own profile must be untouched, in the mode it shipped in")
        .containsEntry(VENDOR_PROFILE, "enforce");
  }

  @Test
  void refusesTheBodyThatWouldSpliceInItsOwnFile() throws IOException {
    String sessionId = newSessionId();

    SandboxExecResult angled = helper("load", sessionId, "  #include </etc/apparmor.d/usr.bin.man>\n  /** r,\n");
    SandboxExecResult trailing = helper("load", sessionId, "  /tmp/z r, #include </etc/apparmor.d/usr.bin.man>\n");

    assertThat(angled.exitCode())
        .as("an include names a file to splice, and only an abstraction may be named: %s", angled.output())
        .isNotZero();
    assertThat(trailing.exitCode())
        .as("apparmor honours an include after a rule on the same line too, measured: %s", trailing.output())
        .isNotZero();
    assertThat(loadedProfiles())
        .containsEntry(VENDOR_PROFILE, "enforce");
  }

  @Test
  void refusesAnAbstractionOtherThanTheOneWardenEmits() throws IOException {
    String sessionId = newSessionId();

    SandboxExecResult refused = helper("load", sessionId, "  include <abstractions/snap_browsers>\n  /** r,\n");
    SandboxExecResult permitted = helper("load", sessionId, WELL_FORMED_BODY);

    assertThat(refused.exitCode())
        .as("an abstraction this project does not emit may declare profiles of its own: %s", refused.output())
        .isNotZero();
    assertThat(permitted.exitCode())
        .as("positive control: the one abstraction warden does emit still loads: %s", permitted.output())
        .isZero();
    helper("unload", sessionId, "");
  }

  @Test
  void loadsTheBodyWhoseRulePathsMerelyContainTheWordInclude() throws IOException {
    String sessionId = newSessionId();

    SandboxExecResult loaded = helper("load", sessionId, "  #include <abstractions/base>\n  /usr/include/** r,\n");

    assertThat(loaded.exitCode())
        .as("a rule over /usr/include is not an include directive: %s", loaded.output())
        .isZero();
    helper("unload", sessionId, "");
  }

  @Test
  void namesTheProfileAnIncludedFileDeclaresAndNotOnlyTheOneWrittenAroundIt(
      @TempDir Path tempDir
  ) throws IOException {
    Optional<Path> declaring = firstAbstractionThatDeclaresProfile();
    assumeTrue(declaring.isPresent(), "this distribution ships no abstraction that declares a profile");
    String wrapper = "warden-sandbox-" + newSessionId();
    Path policy = tempDir.resolve("policy");
    Files.writeString(
        policy,
        "#include <tunables/global>\nprofile " + wrapper + " {\n  include <abstractions/"
            + Path.of("/etc/apparmor.d/abstractions")
                .relativize(declaring.get())
            + ">\n}\n"
    );

    SandboxExecResult declared = TestProcesses.run(List.of("apparmor_parser", "-N", policy.toString()));

    assertThat(declared.output()
        .lines()
        .filter(name -> !name.equals(wrapper))
        .toList())
        .as("the backstop only bounds what an include can bring in if it reads through one: %s",
            declared.output())
        .isNotEmpty();
  }

  @Test
  void refusesEveryArgumentThatIsNotShapedLikeItsOwnSessionId() throws IOException {
    List<String> rejected = List.of(
        "/var/lib/warden/apparmor/anything", "../../etc/apparmor.d/usr.bin.man", "", "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef0123456789abcde"
    );

    for (String candidate : rejected) {
      assertThat(helper("load", candidate, WELL_FORMED_BODY).exitCode())
          .as("the only thing the daemon user may name is a session of its own: %s", candidate)
          .isNotZero();
      assertThat(helper("unload", candidate, "").exitCode())
          .as("and removal takes the same shape: %s", candidate)
          .isNotZero();
    }
    assertThat(helper("reload", newSessionId(), WELL_FORMED_BODY).exitCode())
        .as("an action the helper does not name must not fall through to the parser")
        .isNotZero();
  }

  private static String newSessionId() {
    return UUID.randomUUID()
        .toString()
        .replace("-", "");
  }

  private static SandboxExecResult helper(String action, String sessionId, String body) throws IOException {
    return TestProcesses.run(
        List.of("sudo", AppArmorSessionPolicy.POLICY_HELPER.toString(), action, sessionId), body
    );
  }

  private static Map<String, String> loadedProfiles() throws IOException {
    SandboxExecResult status = TestProcesses.run(List.of("sudo", "aa-status", "--json"));
    assertThat(status.exitCode())
        .as("aa-status must report the kernel's loaded profiles: %s", status.output())
        .isZero();
    return AaStatusProfiles.parse(status.output());
  }

  private static Optional<Path> firstAbstractionThatDeclaresProfile() throws IOException {
    Path abstractions = Path.of("/etc/apparmor.d/abstractions");
    if (!Files.isDirectory(abstractions)) {
      return Optional.empty();
    }
    try (Stream<Path> entries = Files.walk(abstractions)) {
      return entries.filter(Files::isRegularFile)
          .filter(AppArmorPolicyHelperBoundTest::declaresProfile)
          .findFirst();
    }
  }

  private static boolean declaresProfile(Path abstraction) {
    try {
      return Files.readAllLines(abstraction)
          .stream()
          .map(String::strip)
          .anyMatch(line -> (line.startsWith("profile ") || line.startsWith("^")) && line.endsWith("{"));
    } catch (IOException _) {
      return false;
    }
  }
}
