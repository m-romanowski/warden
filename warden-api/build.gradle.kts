description = "Public API contracts for OS-level process sandboxing (macOS Seatbelt, Linux AppArmor+bwrap)"

dependencies {
  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testRuntimeOnly(libs.junit.platform.launcher)
  testImplementation(libs.assertj.core)
}
