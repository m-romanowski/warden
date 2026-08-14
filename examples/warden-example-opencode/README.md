# warden-example-opencode

Sandboxes a real [OpenCode](https://opencode.ai) install instead of a toy shell command, to show warden
wrapping a real, non-trivial third-party CLI with a realistic filesystem+network rule
set (workspace read/write, credential-glob denies, one LLM-provider host allowed).

## Prerequisites

- A real `opencode` executable, either on your `PATH` or passed explicitly:
  ```
  ./gradlew :examples:warden-example-opencode:run --args="--opencode-path /path/to/opencode"
  ```
- To see it do more than print its version, real OpenCode configuration and provider API
  credentials of your own - this example only demonstrates warden's own sandboxing
  wiring, not OpenCode's own setup.

## Run it

```
./gradlew :examples:warden-example-opencode:run
```
