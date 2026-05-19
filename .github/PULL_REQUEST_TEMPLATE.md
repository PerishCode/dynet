## Why

<!-- One short paragraph or a few bullets on what's broken or missing today. -->

## What

<!-- Concrete change list. Reference filenames / modules where helpful. -->

## Tests

<!--
cargo fmt --all --check                                            -> clean
flavor check --root . --config flavor.json                         -> 0 deny
cargo clippy --locked --workspace --all-targets -- -D warnings     -> clean
cargo test --locked --workspace                                    -> N passed
-->

<!--
Optional sections, add when relevant:

## Compatibility
- When config shape, output keys, or exit-code semantics move.

## Trade-off worth flagging
- A known downside reviewers should hold in mind.
-->
