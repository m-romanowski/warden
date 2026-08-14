rootProject.name = "warden"

dependencyResolutionManagement {
  repositories {
    mavenCentral()
  }
}

include(
    ":warden-api",
    ":warden-core",
    ":examples:warden-example-simple",
    ":examples:warden-example-opencode",
)
