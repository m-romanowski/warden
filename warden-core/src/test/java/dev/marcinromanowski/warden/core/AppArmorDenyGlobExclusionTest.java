package dev.marcinromanowski.warden.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AppArmorDenyGlobExclusionTest {

  @Test
  void excludesOneLiteralFromTrailingStarGlob() {
    Optional<List<String>> result = AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.env*", "/workspace/.env.example");

    assertThat(result)
        .isPresent();
    assertThat(result.get())
        .contains("/**/.env.example?*")
        .doesNotContain("/**/.env.example");
  }

  @Test
  void excludesOneLiteralFromLeadingStarGlob() {
    Optional<List<String>> result = AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.pem", "/workspace/safe.pem");

    assertThat(result)
        .isPresent();
    assertThat(result.get())
        .contains("/**/safe?*.pem")
        .doesNotContain("/**/safe.pem");
  }

  @Test
  void eliminatesTheDenyEntirelyWhenItIsExactlyTheExcludedLiteral() {
    Optional<List<String>> result = AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.env", "/workspace/.env");

    assertThat(result)
        .contains(List.of());
  }

  // Not just the recursive-anywhere "/**/" case - a literal directory prefix that exactly matches
  // the excluded path's own directory is supported too (a real, pre-existing test elsewhere in
  // this codebase relies on exactly this shape: a workspace-anchored deny glob like
  // "<tempDir>/.env*", not a recursive one).
  @Test
  void excludesOneLiteralFromTrailingStarGlobUnderLiteralMatchingDirectory() {
    Optional<List<String>> result = AppArmorDenyGlobExclusion.excludeLiteralPath("/workspace/.env*", "/workspace/.env.example");

    assertThat(result)
        .isPresent();
    assertThat(result.get())
        .contains("/workspace/.env.example?*")
        .doesNotContain("/workspace/.env.example");
  }

  @Test
  void fallsBackToEmptyForLiteralDirectoryThatDoesNotMatchTheExcludedPathsOwnDirectory() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/workspace/.env*", "/elsewhere/.env.example"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyForDenyPatternWithNoSlashAtAll() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath(".env*", "/workspace/.env.example"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyForFilenameGlobWithMultipleWildcards() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/*.env*", "/workspace/foo.env.example"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyWhenTheExcludedNameDoesNotActuallyMatchTheGlob() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.env*", "/workspace/readme.txt"))
        .isEmpty();
  }

  @Test
  void fallsBackToEmptyWhenTheExcludedNameContainsUnsafeCharacters() {
    assertThat(AppArmorDenyGlobExclusion.excludeLiteralPath("/**/.env*", "/workspace/.env,evil"))
        .isEmpty();
  }
}
