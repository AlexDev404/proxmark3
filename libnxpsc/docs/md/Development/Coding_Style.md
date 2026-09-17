# Coding style
<a id="top"></a>

C11, formatted as `astyle` would with

```
--style=google --indent=spaces=4 --indent-switches --keep-one-line-blocks
--max-continuation-indent=60 --pad-oper --unpad-paren --pad-header
--align-pointer=name
```

## Conventions

- Public names are `nxpsc_` prefixed. Internal helpers are `static` unless the
  self test needs them, in which case they are declared in `nxpsc_internal.h`.
- Every function that can fail returns `int`, `NXPSC_OK` or a negative
  `nxpsc_error_t`. Out parameters are only written on success.
- Sizes are `size_t`, wire data is `uint8_t`, byte order is spelled out with the
  `put_u16` / `put_u24` / `put_u32` helpers rather than casts.
- Buffers come with a capacity and produce a length. No function writes into a
  caller buffer without being told how large it is.
- No dynamic allocation beyond `nxpsc_open()` and the two places where a command
  payload can exceed a reasonable stack frame.

## Comments

Short and direct, usually one line, matching the surrounding file. A comment
earns its place by saying what the code cannot: where a magic number came from,
a return contract, or why something is deliberately absent. Do not restate the
code and do not put commit message prose in the source.

Preserve existing comments in code you touch or move.

## File headers

New files carry the GPLv3 banner, copied verbatim from a neighbouring file of
the same type.

^[Top](#top)
