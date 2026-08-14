description = "Sandboxing OpenCode with a realistic filesystem+network rule set"

application {
  mainClass.set("dev.marcinromanowski.warden.examples.opencode.Main")
}

dependencies {
  implementation(project(":warden-core"))
}
