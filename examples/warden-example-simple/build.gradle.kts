description = "Sandboxing a plain shell command with an allow/deny filesystem rule"

application {
  mainClass.set("dev.marcinromanowski.warden.examples.simple.Main")
}

dependencies {
  implementation(project(":warden-core"))

  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testRuntimeOnly(libs.junit.platform.launcher)
  testImplementation(libs.assertj.core)
}
