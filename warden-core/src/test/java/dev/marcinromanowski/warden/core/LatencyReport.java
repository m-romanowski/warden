package dev.marcinromanowski.warden.core;

import java.time.Duration;
import java.util.List;
import java.util.Locale;

record LatencyReport(Duration mean, Duration p50, Duration p95, Duration min, Duration max) {

  static LatencyReport of(List<Duration> samples) {
    List<Duration> sorted = samples.stream()
        .sorted()
        .toList();
    long totalNanos = sorted.stream()
        .mapToLong(Duration::toNanos)
        .sum();
    return new LatencyReport(
        Duration.ofNanos(totalNanos / sorted.size()),
        percentile(sorted, 0.50),
        percentile(sorted, 0.95),
        sorted.getFirst(),
        sorted.getLast()
    );
  }

  private static Duration percentile(List<Duration> sorted, double fraction) {
    int index = (int) Math.min(sorted.size() - 1, Math.round(fraction * (sorted.size() - 1)));
    return sorted.get(index);
  }

  String formatted(String label, int sampleCount, int warmupCount) {
    return label + " (" + sampleCount + " samples, " + warmupCount + " warmup, "
        + System.getProperty("os.name") + "/" + System.getProperty("os.arch") + "):"
        + " mean=" + formatMillis(mean)
        + " p50=" + formatMillis(p50)
        + " p95=" + formatMillis(p95)
        + " min=" + formatMillis(min)
        + " max=" + formatMillis(max);
  }

  private static String formatMillis(Duration duration) {
    return String.format(Locale.ROOT, "%.3fms", duration.toNanos() / 1_000_000.0);
  }
}
