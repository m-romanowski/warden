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

  // AppArmor requires every pattern to be an absolute path - a relative-looking "anywhere in the
  // tree" pattern (no leading "/", meaningful only as a java.nio.file glob against an
  // already-absolute candidate) needs one prepended, confirmed empirically on a real kernel that
  // this preserves the intended "anywhere, including at the filesystem root" meaning exactly.
  @Test
  void prependsLeadingSlashToRelativeAnywherePattern() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern("**/*.pem"))
        .isEqualTo("/**/*.pem");
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
}
