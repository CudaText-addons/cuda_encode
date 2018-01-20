Plugin for CudaText.
Allows to convert text (selected block or entire text if nothing selected) using many codings (transformations).
Ported from StringEncode: https://github.com/colinta/SublimeStringEncode
Later more codings were added.

Codings:

- HTML entitize: Converts characters to their HTML entity "&nnn;"
- HTML deentitize: Converts HTML entities to characters
- XML entitize: Converts characters to their XML entity
- XML deentitize: Converts XML entities to characters
- Safe HTML entitize: Converts characters to their HTML entity, but preserves HTML reserved characters
- Safe HTML deentitize: Converts HTML entities to characters, but preserves HTML reserved characters

- JSON escape: Escapes a string and surrounds it in quotes, according to the JSON encoding
- JSON unescape: Unescapes a string (including the quotes!) according to JSON encoding
- URL encode: Uses urllib.quote to escape special URL characters
- URL decode: Uses urllib.unquote to convert escaped URL characters

- Base64 encode/decode
- Base32 encode/decode
- Base16 encode/decode

- Quoted-printable: converts Unicode string to smth like =D0=9F=D1=80=D0=BE
- Unicode-escape: converts Unicode string to smth like \u041f\u0440\u043e

- MD5: Creates MD5 hash
- SHA256: Creates SHA256 hash
- SHA512: Creates SHA512 hash

- Escape regex: Escapes reg.ex. meta characters
- Escape LIKE: Escapes SQL-LIKE meta characters

- Decimal to Hex: converts decimal number to hex form (with 0x prefix)
- Hex to Decimal: converts hex number (0x prefix is optional) to decimal form

- Unicode Normalize (NFC, NFD, NFKC, NFKD): see description at https://en.wikipedia.org/wiki/Unicode_equivalence#Normal_forms 


Author: Alexey T (CudaText)
License: MIT
