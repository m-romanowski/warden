package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class AppArmorGlobTranslatorTest {

  @Test
  void passesThroughAlreadyAbsoluteGlobSyntaxUnchanged() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern("/workspace/**"))
        .isEqualTo("/workspace/**");
  }

  @Test
  void prependsLeadingSlashToRelativeAnywherePattern() {
    // AppArmor requires every pattern to be an absolute path - a relative-looking "anywhere in the
    // tree" pattern (no leading "/", meaningful only as a java.nio.file glob against an
    // already-absolute candidate) needs one prepended. It does not preserve the "at the filesystem
    // root" end of that meaning. AppArmor's "**" does not match the empty string between two slashes.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern("**/*.pem"))
        .isEqualTo("/**/*.pem");
  }

  @Test
  void namesTheRootLevelReadingALeadingRecursiveGlobDoesNotCover() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/.env"))
        .containsExactly("/.env");
  }

  @Test
  void namesEveryDepthARepeatedLeadingRecursiveGlobDoesNotCover() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/**/.env"))
        .containsExactly("/**/.env", "/.env");
  }

  @Test
  void namesNoRootLevelReadingForAPatternWithoutALeadingRecursiveGlob() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/workspace/**/.env"))
        .isEmpty();
  }

  @Test
  void refusesTheRootLevelReadingThatWouldNameTheFilesystemRootItself() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/"))
        .isEmpty();
  }

  @Test
  void expandsUserHomeTokenBeforeTranslation() {
    String userHome = System.getProperty("user.home");

    assertThat(AppArmorGlobTranslator.toAppArmorPattern("${user.home}/.aws/credentials"))
        .isEqualTo(userHome + "/.aws/credentials");
  }

  @Test
  void rejectsBracketCharacterClass() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("**/*.[jJ][sS]"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsBraceGroup() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("**/*.{env,pem}"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsCommaAsRuleSyntaxInjectionRisk() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("**/evil, deny /** rwx, #.env"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsLineBreakAsRuleSyntaxInjectionRisk() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("**/evil\n/** rwx,"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsBackslashBecauseAppArmorReadsItAsAnEscape() {
    // '\' is a legal character in a Linux filename and callers interpolate real paths into patterns,
    // but AppArmor reads it as an escape, so a rule set scoped to a directory named "work\space" is
    // parsed as naming "workspace" - measured on a real kernel to grant read-write on that other
    // directory and to refuse every write inside the intended one. A component ending in '\' makes
    // apparmor_parser reject the whole profile, which is a failed launch rather than a rejected rule.
    // SeatbeltGlobTranslator already refused it, so accepting it here made one rule set mean two
    // different things.
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("/home/user/work\\space/**"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsTrailingBackslashThatWouldMakeTheParserRefuseTheWholeProfile() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern("/home/user/trailing\\"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
