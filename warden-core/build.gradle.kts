description = "Platform enforcement (macOS Seatbelt, Linux AppArmor+bwrap network bridge) implementing the warden-api contracts"

dependencies {
  api(project(":warden-api"))
  implementation(libs.jetty.server)
  implementation(libs.jetty.proxy)
  implementation(libs.jetty.unixdomain.server)

  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testRuntimeOnly(libs.junit.platform.launcher)
  testImplementation(libs.assertj.core)
}

tasks.test {
  inputs.file(rootProject.file("scripts/install-apparmor-bwrap-override.sh"))
}

tasks.register<Test>("benchmark") {
  description = "Runs real, wall-clock latency benchmarks"
  group = "verification"
  testClassesDirs = sourceSets.test.get().output.classesDirs
  classpath = sourceSets.test.get().runtimeClasspath
  useJUnitPlatform {
    includeTags("benchmark")
  }
  outputs.upToDateWhen { false }
  testLogging {
    showStandardStreams = true
  }
}
