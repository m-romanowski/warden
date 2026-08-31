package dev.marcinromanowski.warden.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

final class LinuxNetworkNamespaces {

  private static final Path PROC = Path.of("/proc");
  private static final String ARGUMENT_SEPARATOR = "\0";

  private LinuxNetworkNamespaces() {
  }

  static Optional<String> of(long pid) {
    try {
      Path link = PROC.resolve(Long.toString(pid))
          .resolve("ns/net");
      return Optional.of(
          Files.readSymbolicLink(link)
              .toString()
      );
    } catch (IOException | RuntimeException _) {
      return Optional.empty();
    }
  }

  static List<NetworkNamespaceMember> membersOf(String networkNamespace) {
    List<NetworkNamespaceMember> members = new ArrayList<>();
    try (Stream<Path> entries = Files.list(PROC)) {
      entries.map(entry -> entry.getFileName()
              .toString())
          .filter(LinuxNetworkNamespaces::isNumeric)
          .map(Long::parseLong)
          .filter(pid -> isIn(pid, networkNamespace))
          .forEach(pid -> members.add(memberAt(pid)));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return List.copyOf(members);
  }

  private static boolean isIn(long pid, String networkNamespace) {
    return of(pid)
        .filter(networkNamespace::equals)
        .isPresent();
  }

  private static NetworkNamespaceMember memberAt(long pid) {
    List<String> argv = argvOf(pid);
    String executableName = argv.isEmpty()
        ? ""
        : Path.of(argv.getFirst())
            .getFileName()
            .toString();
    return new NetworkNamespaceMember(pid, executableName, String.join(" ", argv));
  }

  private static List<String> argvOf(long pid) {
    try {
      Path commandLine = PROC.resolve(Long.toString(pid))
          .resolve("cmdline");
      String raw = new String(Files.readAllBytes(commandLine), StandardCharsets.UTF_8);
      return Stream.of(raw.split(ARGUMENT_SEPARATOR))
          .filter(argument -> !argument.isEmpty())
          .toList();
    } catch (IOException | RuntimeException _) {
      return List.of();
    }
  }

  private static boolean isNumeric(String name) {
    return !name.isEmpty() && name.chars()
        .allMatch(Character::isDigit);
  }
}
