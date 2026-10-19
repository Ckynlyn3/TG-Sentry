# Third-party notices

## AegisHook

- Project: [RuoJi6/AegisHook](https://github.com/RuoJi6/AegisHook)
- Author: RuoJi6 and AegisHook contributors.
- License: MIT. The repository LICENSE is PolyForm Noncommercial 1.0.0; AegisHook's complete MIT copyright and license text is reproduced verbatim at the end of this file.
- Imported source: commit `e98e59f12a213216e0dd5d6f5494d3df7ecc7070`.
- The original README is preserved in [docs/aegishook/README.md](docs/aegishook/README.md).

## ARTEX

- Project: [Autumn-27/ARTEX](https://github.com/Autumn-27/ARTEX)
- Author attribution: Autumn-27.
- License: MIT.
- Scope: prompt and regular-expression fragments adapted by AegisHook; TG-Sentry inherits those fragments through the AegisHook source import, not a separate ARTEX source-tree import.
- Attribution source: the final references in [AegisHook's README at the imported commit](https://github.com/RuoJi6/AegisHook/blob/e98e59f12a213216e0dd5d6f5494d3df7ecc7070/README.md) name `https://github.com/Autumn-27/ARTEX`. That README also references [Ed1s0nZ/CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI). AegisHook has no separate tracked NOTICE file at this commit.

## libphonenumber metadata

- Copyright (C) 2009 The Libphonenumber Authors.
- The CN/mobile number-pattern data in `internal/eval/pii.go` is ported from [PhoneNumberMetadata.xml at v9.0.17](https://github.com/google/libphonenumber/blob/v9.0.17/resources/PhoneNumberMetadata.xml), with decimal digit notation adapted for Go regexp.
- License: Apache-2.0; full upstream text is preserved in [docs/licenses/libphonenumber-LICENSE](docs/licenses/libphonenumber-LICENSE).
- This is a data-pattern port only, not a new Go dependency.

## Gitleaks

- Project: [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks).
- Pinned source: commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`.
- Scope: the nine-rule subset and synthetic fixture shape/expectations from `config/gitleaks.toml`, `config/allowlist.go`, `detect/detect.go`, `detect/utils.go`, and `cmd/generate/config/utils/validate.go`. Synthetic candidates are generated locally; upstream positive samples are not copied.
- Configuration SHA-256: `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
- License: MIT; the complete pinned upstream license follows.

```text
MIT License

Copyright (c) 2019 Zachary Rice

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

## Prompt-attack pattern adaptations

`internal/core/prompt_attack_patterns.go` contains modified pattern fragments and
structural indicators, not forks of the upstream scanners. Synthetic development
fixtures are authored locally; no benchmark items were used.

- **Rebuff:** protectai/rebuff commit `4d2fe064abf164e7381556d23e48e210080f8afa`,
  [`python-sdk/rebuff/detect_pi_heuristics.py:16–69`](https://github.com/protectai/rebuff/blob/4d2fe064abf164e7381556d23e48e210080f8afa/python-sdk/rebuff/detect_pi_heuristics.py#L16-L69).
  Copyright 2023 The Rebuff AI Authors. Apache-2.0; the complete standard license
  text is already retained in [docs/licenses/libphonenumber-LICENSE](docs/licenses/libphonenumber-LICENSE).
  Changes: use only instruction-override phrase structure, require a prior-context
  qualifier, compile with Go RE2 and add word boundaries. The broad Chinese
  translation is a non-terminal indicator only; no fuzzy scoring, general
  content/text keywords or upstream thresholds are ported.
- **Vigil:** deadbits/vigil-llm commit `f2b4c134d060bae81d29fad07003f3c657e63fc8`,
  [`data/yara/instruction_bypass.yar:9`](https://github.com/deadbits/vigil-llm/blob/f2b4c134d060bae81d29fad07003f3c657e63fc8/data/yara/instruction_bypass.yar#L9),
  [`data/yara/mdexfil.yar:10`](https://github.com/deadbits/vigil-llm/blob/f2b4c134d060bae81d29fad07003f3c657e63fc8/data/yara/mdexfil.yar#L10), and
  [`data/yara/system_instructions.yar:12–16`](https://github.com/deadbits/vigil-llm/blob/f2b4c134d060bae81d29fad07003f3c657e63fc8/data/yara/system_instructions.yar#L12-L16).
  Author attribution: Adam M. Swanda. Apache-2.0 (same complete standard license
  linked above). Changes: instruction-override narrowing as above; adapt Markdown
  query URLs and conversation markers into non-terminal structural indicators.
  No YARA execution or upstream blocking policy is imported. Neither pinned
  Rebuff nor Vigil tree includes a separate NOTICE file.
- **AgentSentry:** ling101w/AgentSentry- commit
  `50553611c7eb4a25fdfdde37934c1b919a9dcd3e`,
  [`openclaw-plugin/core/detect.ts:74–83`](https://github.com/ling101w/AgentSentry-/blob/50553611c7eb4a25fdfdde37934c1b919a9dcd3e/openclaw-plugin/core/detect.ts#L74-L83).
  MIT; idea source for bilingual regex style and existing bounded gap widths,
  not an imported scanner. Changes: retain structured instruction override,
  safety bypass and unrestricted-role phrases, translate their explicit targets,
  and omit broad prompt/configuration/secret nouns as terminal matches. Broad
  Chinese instruction/safety-override gaps are indicators only after S1 review;
  they cannot establish malicious intent from verbs and nouns alone.
- **LLM Guard:** protectai/llm-guard commit
  `168c1034ffdb33837e7ae6fd6a16b80567c1be03`,
  [`llm_guard/input_scanners/invisible_text.py:21,31–37`](https://github.com/protectai/llm-guard/blob/168c1034ffdb33837e7ae6fd6a16b80567c1be03/llm_guard/input_scanners/invisible_text.py#L21-L37).
  MIT. Changes: recognize only Unicode category Cf, strip it from a matching
  copy, and emit a non-terminal indicator without logging characters. Private-use
  and unassigned characters are not removed; no learned model is imported.

### AgentSentry MIT license

Copyright (c) 2026 AgentSentry contributors

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

### LLM Guard MIT license

Copyright (c) Protect AI. All rights reserved.

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

Other dependencies remain subject to their respective licenses. Upstream's `scripts/write-notices.mjs` generates dependency-license notices for packaged builds; it is preserved unchanged.

## shadcn/ui

- Project: [shadcn-ui/ui](https://github.com/shadcn-ui/ui).
- Copyright (c) 2023 shadcn.
- Pinned source: commit `daaf156ee00ed91cc7e6bdd937c1b4973152d141`.
- Scope: the chart primitive ported into `console/src/components/ui/chart.tsx`.
- License: MIT; the complete upstream license text is preserved in [console/src/components/ui/chart.LICENSE.md](console/src/components/ui/chart.LICENSE.md).

## Recharts

- Project: [recharts/recharts](https://github.com/recharts/recharts).
- Copyright (c) 2015-present recharts.
- Version: 3.8.0, a console runtime dependency (`console/package.json`).
- License: MIT.

## Casdoor

- Project: [casdoor/casdoor](https://github.com/casdoor/casdoor).
- Copyright 2021 The Casdoor Authors. All Rights Reserved.
- Pinned release: [v4.21.0](https://github.com/casdoor/casdoor/tree/v4.21.0),
  commit `2e0a10c97d949fc88b1f1505fe19db35c880645d`.
- Deployment image: `casbin/casdoor:4.21.0@sha256:54a85f9dfc0096f81d2e8f33ebab1123f10f952fd28284d1435b78a1ab5038fa`.
- Scope: optional external identity broker in `deploy/docker-compose.yml`;
  configuration and smoke API usage adapted from the Casdoor documentation.
  No Casdoor source is linked into the TG-Sentry binary. The child-host redirect
  caveat blocks using this candidate as the default issuer; see
  [deployment instructions](deploy/casdoor/README.md).
- License: [Apache License 2.0 at the pinned release](https://github.com/casdoor/casdoor/blob/v4.21.0/LICENSE).
  Apache-2.0 terms §§1–9 are retained unchanged in
  [docs/licenses/libphonenumber-LICENSE](docs/licenses/libphonenumber-LICENSE);
  the upstream link also includes Apache's instructional appendix.
  This attribution and the license links preserve the Apache-2.0 §4 notice;
  the pinned Casdoor source tree has no separate NOTICE file. Modified material:
  PostgreSQL Compose configuration, operator placeholders, and a disposable
  release-verification script; upstream source is unmodified.

---

## AegisHook — full MIT license text (upstream, preserved verbatim)

```
MIT License

Copyright (c) 2026 RuoJi6 and AegisHook contributors

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
