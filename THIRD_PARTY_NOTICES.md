# Third-Party Notices

This service adapts selected document-access parsing, asset URL resolution,
premium-locked page detection, HTML fragment sanitization, and print page-size
layout concepts from the MIT-licensed project below.

## StudocuHack

- Repository: https://github.com/danieltyukov/studocuhack
- Pinned revision: fbb2ba270450ec26a55a75448070fa13ebb641a9
- Reference files: `docs/ARCHITECTURE.md`, `src/content/common.js`, `src/content/pages.js`, `src/content/download.js`
- Adapted scope:
  - Normalized `documentAccess` parsing (`signedQueryParams` text vs scanned modes)
  - Hex background asset numbering (`bg{hex}.png`) vs decimal text fragment numbering (`{objectKey}{n}.page`)
  - Locked-page detection keyed off `Array.isArray(signedQueryParams.pages)` rather than length or mutable blur flags
  - HTML fragment sanitization and `.p2hv` print container `@page` sizing

```text
MIT License

Copyright (c) 2024 Daniel Tyukov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
