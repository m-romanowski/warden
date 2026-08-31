package dev.marcinromanowski.warden.api;

import java.nio.file.Path;
import java.util.Objects;

/**
 * What a {@link FilesystemRule} is matched against - a {@code java.nio.file} glob, or one exact
 * path.
 *
 * <p>Which of the two a caller means is something only the caller knows, and there is no spelling
 * that is safe to guess at. {@code /home/me/My*Project/**} is a rule over four hundred sibling
 * directories if the {@code "*"} is a wildcard and a rule over one directory if it is part of that
 * directory's real name, and a translator handed the bare string picks one of those and says
 * nothing. So the question is asked here, at the only point that can answer it, and every rule
 * carries the answer.
 *
 * <p>{@link #glob} is the pattern language: {@code "**"} spans separators, {@code "*"} spans a path
 * segment, {@code "?"} is one character, and {@code "\"} escapes whatever follows it. Every other
 * {@code java.nio.file} glob construct - a {@code "[...]"} character class, a {@code "{a,b}"}
 * alternation - is refused rather than translated, because neither platform's policy language has
 * one and a translation that quietly turned a group into a filename would produce a rule matching
 * nothing at all.
 *
 * <p>{@link #literal} takes a path and means every byte of it, wildcards included. {@link #tree}
 * is that path and everything under it. Both are {@link #quote}d and so need no escaping by the
 * caller, and {@link #quote} is public for the caller building a pattern out of literal fragments
 * and wildcards of its own.
 */
public final class RulePath {

  private static final String GLOB_METACHARACTERS = "\\*?[]{}";
  private static final String RECURSIVE_SUFFIX = "/**";
  private static final char ESCAPE = '\\';

  private final String pattern;

  private RulePath(String pattern) {
    this.pattern = pattern;
  }

  /** A glob pattern, in the language this class documents. */
  public static RulePath glob(String pattern) {
    return new RulePath(Preconditions.nonBlank(pattern, "pattern"));
  }

  /** One exact path - every character of it literal, including {@code "*"} and {@code "?"}. */
  public static RulePath literal(String path) {
    return new RulePath(quote(Preconditions.nonBlank(path, "path")));
  }

  /** One exact path - every character of it literal, including {@code "*"} and {@code "?"}. */
  public static RulePath literal(Path path) {
    Path required = Preconditions.nonNull(path, "path");
    return literal(required.toString());
  }

  /**
   * Everything under one exact directory. The directory entry itself is a rule of its own - see
   * {@link #literal} - because a pattern matching descendants does not match the directory a
   * process has to open to reach them.
   */
  public static RulePath tree(String directory) {
    return new RulePath(quote(Preconditions.nonBlank(directory, "directory")) + RECURSIVE_SUFFIX);
  }

  /** Everything under one exact directory. */
  public static RulePath tree(Path directory) {
    Path required = Preconditions.nonNull(directory, "directory");
    return tree(required.toString());
  }

  /**
   * The glob spelling of a literal fragment, for a caller composing a pattern that is partly its
   * own wildcards and partly a path it holds - {@code quote(root) + "/**&#47;.env"}.
   */
  public static String quote(String literalFragment) {
    String required = Preconditions.nonNull(literalFragment, "literalFragment");
    StringBuilder quoted = new StringBuilder(required.length());
    required.codePoints()
        .forEach(codePoint -> appendQuoted(quoted, codePoint));
    return quoted.toString();
  }

  private static void appendQuoted(StringBuilder quoted, int codePoint) {
    if (GLOB_METACHARACTERS.indexOf(codePoint) >= 0) {
      quoted.append(ESCAPE);
    }
    quoted.appendCodePoint(codePoint);
  }

  /** The pattern, in glob syntax, escapes included. */
  public String pattern() {
    return pattern;
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof RulePath rulePath && pattern.equals(rulePath.pattern);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(pattern);
  }

  @Override
  public String toString() {
    return pattern;
  }
}
