# Contributing
<a id="top"></a>

## Before opening a pull request

- `cmake -S . -B build && cmake --build build && cd build && ctest` must pass.
- Build warning free with both gcc and clang. Warnings are treated as errors in
  the CI, and are not to be silenced with pragmas or flags.
- New protocol behaviour needs a test. A command that only ever ran against a
  card you happen to own is a command nobody else can maintain.
- State in the pull request which of Linux, macOS and Windows you built on, and
  which card, if any, you tried it against. Be explicit about what you did not
  test.

## Pull request description

- **Problem** - the concrete symptom, not "the code is messy".
- **Change** - what you did, and why this approach.
- **Behaviour change** - anything a caller could observe differently, as its own
  section, even when the new behaviour is strictly more correct.
- **Testing** - exact build variants exercised, and what was left untested.

## Protocol claims need a source

When adding or correcting a command, cite where the format came from: an NXP
application note, a datasheet table, or a cross check against another
implementation. The reference implementations disagree in places, see
[Porting notes](Porting_Notes.md), so "it works on my card" is not enough on its
own.

^[Top](#top)
