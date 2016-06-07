Plugin for CudaText.
Allows to convert text (selected block or entire text if nothing selected)
using many codings (transformations).
Ported from StringEncode: 
https://github.com/colinta/SublimeStringEncode


Codings of original plugin
(copy/paste from readme)

- html_entitize: Converts characters to their HTML entity

- html_deentitize: Converts HTML entities to a character

- url_encode: Uses urllib.quote to escape special URL characters.
  Accepts an old_school argument (default: True).  Setting it to False
  will return %20 instead of + when encoding spaces.

- url_decode: Uses urllib.unquote to convert escaped URL characters

- json_escape: Escapes a string and surrounds it in quotes, according to the JSON encoding.

- json_unescape: Unescapes a string (include the quotes!) according to JSON encoding.

- base64_encode: Uses base64 to encode into base64

- base64_decode: Uses base64 to decode from base64

- md5_encode: Uses sha package to create md5 hash

- sha256_encode: Uses sha package to create sha256 hash

- sha512_encode: Uses sha package to create sha512 hash

- escape_regex: Escapes regex meta characters

- escape_like: Escapes SQL-LIKE meta characters

- safe_html_entitize: Converts characters to their HTML entity, but preserves HTML reserved characters

- safe_html_deentitize: Converts HTML entities to a character, but preserves HTML reserved characters

- xml_entitize: Converts characters to their XML entity

- xml_deentitize: Converts XML entities to a character


Author: Alexey T (CudaText)
