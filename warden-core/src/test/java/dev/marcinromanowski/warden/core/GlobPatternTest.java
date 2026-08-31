package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.marcinromanowski.warden.api.RulePath;
import dev.marcinromanowski.warden.api.SandboxRuleRejectedException;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GlobPatternTest {

  @ParameterizedTest
  @ValueSource(strings = {"**/*.{pem,key}", "**/[.]env", "/w/{a,b}/**", "/w/x[0-9].pem"})
  void refusesTheConstructNeitherPolicyLanguageHas(String pattern) {
    assertThatThrownBy(() -> GlobPattern.parse(pattern))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .asInstanceOf(InstanceOfAssertFactories.type(SandboxRuleRejectedException.class))
        .extracting(SandboxRuleRejectedException::targetPattern)
        .isEqualTo(pattern);
  }

  @Test
  void bothTranslatorsRefuseTheSameConstruct() {
    RulePath braceGroup = RulePath.glob("**/*.{pem,key}");

    assertThatThrownBy(() -> AppArmorGlobTranslator.toAppArmorPattern(braceGroup))
        .isInstanceOf(SandboxRuleRejectedException.class);
    assertThatThrownBy(() -> SeatbeltGlobTranslator.toRegex(braceGroup))
        .isInstanceOf(SandboxRuleRejectedException.class);
  }

  @Test
  void acceptsTheEscapedSpellingOfTheRefusedConstruct() {
    assertThat(GlobPattern.parse("/w/a\\{b"))
        .containsExactly(
            new GlobLiteral('/'), new GlobLiteral('w'), new GlobLiteral('/'),
            new GlobLiteral('a'), new GlobLiteral('{'), new GlobLiteral('b')
        );
  }

  @Test
  void readsTheSupportedWildcardsAsWildcardsAndEverythingElseAsItself() {
    assertThat(GlobPattern.parse("**/a*b?c"))
        .containsExactly(
            GlobWildcard.ANY_PATH, new GlobLiteral('/'), new GlobLiteral('a'),
            GlobWildcard.ANY_SEGMENT, new GlobLiteral('b'),
            GlobWildcard.SINGLE_CHARACTER, new GlobLiteral('c')
        );
  }

  @Test
  void readsAnEscapedWildcardAsTheCharacterItIs() {
    assertThat(GlobPattern.parse("a\\*b"))
        .containsExactly(new GlobLiteral('a'), new GlobLiteral('*'), new GlobLiteral('b'));
  }

  @Test
  void refusesThePatternEndingInAnEscapeWithNothingToEscape() {
    assertThatThrownBy(() -> GlobPattern.parse("/w/trailing\\"))
        .isInstanceOf(SandboxRuleRejectedException.class)
        .hasMessageContaining("backslash");
  }

  @Test
  void quotesTheHomeDirectoryItSubstitutesRatherThanSplicingIt() {
    RulePath substituted = RulePath.glob("${user.home}/.aws/credentials");
    RulePath spelledOut = RulePath.literal(System.getProperty("user.home") + "/.aws/credentials");

    assertThat(GlobPattern.parse(substituted.pattern()))
        .containsExactlyElementsOf(GlobPattern.parse(spelledOut.pattern()));
  }

  @Test
  void literalAndGlobDisagreeAboutTheWildcardAndAboutNothingElse() {
    assertThat(GlobPattern.parse(RulePath.literal("/w/My*Project").pattern()))
        .containsExactlyElementsOf(GlobPattern.parse("/w/My\\*Project"));
    assertThat(GlobPattern.parse(RulePath.glob("/w/My*Project").pattern()))
        .contains(GlobWildcard.ANY_SEGMENT);
  }
}
