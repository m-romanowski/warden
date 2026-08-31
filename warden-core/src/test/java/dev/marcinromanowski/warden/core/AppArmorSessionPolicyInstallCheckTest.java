package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

@EnabledOnOs(OS.LINUX)
class AppArmorSessionPolicyInstallCheckTest {

  @Test
  void acceptsTheHelperOnlyRootCanRewrite() {
    assertThat(AppArmorSessionPolicy.rootOwnedAndOnlyRootWritable(AppArmorSessionPolicy.POLICY_HELPER))
        .as("positive control, and the install step's own verdict: the helper this machine is"
            + " running has to be one this user cannot rewrite")
        .isEmpty();
  }

  @Test
  void refusesTheHelperThisUserOwns(@TempDir Path tempDir) throws IOException {
    Path helper = Files.createFile(tempDir.resolve("helper"));

    assertThat(AppArmorSessionPolicy.rootOwnedAndOnlyRootWritable(helper))
        .hasValueSatisfying(problem -> assertThat(problem)
            .contains("not owned by root")
        );
  }

  @Test
  void refusesTheRootOwnedHelperAnyoneElseCanWrite() {
    assertThat(AppArmorSessionPolicy.rootOwnedAndOnlyRootWritable(Path.of("/tmp")))
        .as("/tmp is root-owned and mode 1777, which is the second half of the check")
        .hasValueSatisfying(problem -> assertThat(problem)
            .contains("writable by a group or by everyone")
        );
  }
}
