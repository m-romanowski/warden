package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import org.junit.jupiter.api.Test;

class AppArmorGlobTranslatorTest {

  @Test
  void passesThroughAlreadyAbsoluteGlobSyntaxUnchanged() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.glob("/workspace/**")))
        .isEqualTo("/workspace/**");
  }

  @Test
  void prependsLeadingSlashToRelativeAnywherePattern() {
    // AppArmor requires every pattern to be an absolute path - a relative-looking "anywhere in the
    // tree" pattern (no leading "/", meaningful only as a java.nio.file glob against an
    // already-absolute candidate) needs one prepended. It does not preserve the "at the filesystem
    // root" end of that meaning. AppArmor's "**" does not match the empty string between two slashes.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.glob("**/*.pem")))
        .isEqualTo("/**/*.pem");
  }

  @Test
  void namesTheRootLevelReadingTheLeadingRecursiveGlobDoesNotCover() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/.env"))
        .containsExactly("/.env");
  }

  @Test
  void namesEveryDepthTheRepeatedLeadingRecursiveGlobDoesNotCover() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/**/.env"))
        .containsExactly("/**/.env", "/.env");
  }

  @Test
  void namesNoRootLevelReadingForPatternsWithoutTheLeadingRecursiveGlob() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/workspace/**/.env"))
        .isEmpty();
  }

  @Test
  void refusesTheRootLevelReadingThatWouldNameTheFilesystemRootItself() {
    assertThat(AppArmorGlobTranslator.zeroSegmentForms("/**/"))
        .isEmpty();
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void escapesSpacesInsteadOfLettingThemEndTheClause() {
    // A clause is "<pattern> <access-mode>," on one unquoted line, so a bare space makes the parser
    // read the rest of the path as the mode - measured, a whole profile refused for a workspace
    // whose directory name has a space in it, which is an ordinary thing for one to have.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/home/user/my project")))
        .isEqualTo("/home/user/my\\040project/**");
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void escapesTheOtherCharactersThisGrammarGivesMeaningTo() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/w/a,b/c#d/e{f}g/h[i]j/k!l/m\tn")))
        .isEqualTo("/w/a\\054b/c\\043d/e\\173f\\175g/h\\133i\\135j/k\\041l/m\\011n/**");
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void escapesLineBreaksInsteadOfEndingTheClauseMidPath() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.literal("/w/evil\n/** rwx,")))
        .isEqualTo("/w/evil\\012/\\052\\052\\040rwx\\054");
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void escapesBackslashesInsteadOfLettingAppArmorReadThemAsAnEscape() {
    // AppArmor reads a bare backslash as an escape, so a rule set scoped to a directory named
    // "work\space" was parsed as naming "workspace" - measured on a real kernel to grant read-write
    // on that other directory and refuse every write inside the intended one. A component ending in
    // one made apparmor_parser refuse the whole profile.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/home/user/work\\space")))
        .isEqualTo("/home/user/work\\134space/**");
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.literal("/home/user/trailing\\")))
        .isEqualTo("/home/user/trailing\\134");
  }

  @Test
  void escapesEachByteOfNonAsciiCharactersSeparately() {
    // A path is a byte string to the parser and to the kernel alike, so a character escaped as one
    // unit would name a path no filesystem holds.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/w/praća")))
        .isEqualTo("/w/pra\\304\\207a/**");
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void keepsTheGlobSyntaxTheCallerWroteLive() {
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(
        RulePath.glob(RulePath.quote("/w/my project") + "/**/*.p?m")
    ))
        .isEqualTo("/w/my\\040project/**/*.p?m");
  }

  @Test
  void escapesTheWildcardTheCallerAskedToBeReadLiterally() {
    // The one asterisk a caller can mean two ways. Live, it is AppArmor's own wildcard byte. Escaped
    // or named through a literal, it is "\052" - and a directory really named "My*Project" is then
    // the only one the clause reaches. Measured on a real kernel in AppArmorPathEscapingTest.
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.tree("/w/My*Project")))
        .isEqualTo("/w/My\\052Project/**");
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.glob("/w/My\\*Project/**")))
        .isEqualTo("/w/My\\052Project/**");
    assertThat(AppArmorGlobTranslator.toAppArmorPattern(RulePath.glob("/w/My*Project/**")))
        .isEqualTo("/w/My*Project/**");
  }

  @Test
  @SuppressWarnings("checkstyle:IllegalTokenText")
  void namesTheRootLevelReadingOfAnEscapedPatternToo() {
    String pattern = AppArmorGlobTranslator.toAppArmorPattern(
        RulePath.glob("**/" + RulePath.quote(".env b"))
    );

    assertThat(AppArmorGlobTranslator.zeroSegmentForms(pattern))
        .containsExactly("/.env\\040b");
  }

  @Test
  void refusesDoubleQuotesBecauseTheOtherPlatformCannotExpressOne() {
    // AppArmor could carry one. macOS Seatbelt cannot: a pattern is emitted there as a regex inside
    // a #"..." literal whose only terminator is that same character, with no escape for it. Refused
    // on both so one rule list does not mean two different policies.
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern(RulePath.literal("/w/report\".pem")))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("double quote");
  }

  @Test
  void refusesNulBytesBecauseNoPathCanHoldOne() {
    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern(RulePath.glob("/w/evil\0/**")))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("NUL");
  }
}
