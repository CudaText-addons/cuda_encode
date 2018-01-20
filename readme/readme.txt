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

- Base64 encode
- Base64 decode
- Base32 encode
- Base32 decode
- Base16 encode
- Base16 decode

- MD5: Uses sha package to create md5 hash
- SHA256: Uses sha package to create sha256 hash
- SHA512: Uses sha package to create sha512 hash

- Escape regex: Escapes reg. ex. meta characters
- Escape LIKE: Escapes SQL-LIKE meta characters


Author: Alexey T (CudaText)
License: MIT
