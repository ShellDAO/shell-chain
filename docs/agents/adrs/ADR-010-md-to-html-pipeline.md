# ADR-010: Markdown → HTML Build-Time Rendering Pipeline for `shell-site`

- **Status**: accepted
- **Date**: 2026-05-13
- **Authors**: shell-chain core (distilled by AI agent)
- **Related**: `shell-site/lib/content.ts`; `shell-site/components/content/HtmlContent.tsx`; (historical plan-md-html-refactor.md session artefact)

## Context

`shell-site` serves docs and blog content authored as `.md` files. The original
architecture used a client-side `MarkdownRenderer` React component
(`react-markdown + remark-gfm + rehype-slug`) that received the raw Markdown
string as a prop and parsed it in the browser. This had three problems:

1. **Client bundle bloat**: `react-markdown`, `remark-gfm`, and related
   dependencies shipped to every visitor, increasing JS parse time and hydration
   cost on content pages that do not require interactivity.
2. **No HTML sanitization**: Markdown rendered directly via `react-markdown`
   applied no explicit allowlist. A malicious content PR could inject unsafe
   HTML attributes or `<script>` tags via raw HTML blocks.
3. **Runtime rendering cost**: Markdown-to-HTML conversion ran on every page
   load rather than at build time. Because `next.config.ts` uses
   `output: "export"` (static export), the compilation result is the same for
   every visitor — doing it at runtime wastes CPU.

Additionally, the frontmatter parser in `shell-site/lib/blog.ts` was a handwritten
line-based parser, fragile against edge cases in multi-line frontmatter values.

## Decision

Transform Markdown to HTML **at build time** using the
`unified / remark / rehype` pipeline; serve sanitized HTML server-side via a
`HtmlContent` server component. The key components of the decision:

1. **`shell-site/lib/content.ts`** is the single source of truth for content
   loading. It accepts both `.md` and `.html` source files, parses frontmatter
   with `gray-matter`, converts Markdown via
   `remark-parse → remark-gfm → remark-rehype → rehype-slug → rehype-stringify`,
   and sanitizes the output with an explicit allowlist (`rehype-sanitize` or
   `sanitize-html`).

2. **`shell-site/components/content/HtmlContent.tsx`** is the only component
   allowed to use `dangerouslySetInnerHTML`, and only after content has passed
   the sanitizer. `MarkdownRenderer`, `react-markdown`, and `next-mdx-remote`
   are removed from the main rendering path.

3. **Strict frontmatter schema**: every content document must declare `title`.
   Optional fields: `description`, `date`, `author`, `excerpt`, `tags`, `order`.
   The `gray-matter` parser handles multi-line values and YAML edge cases
   correctly.

4. **Native `.html` content lane**: `.html` files are accepted beside `.md`
   files under `content/docs/` and `content/blog/`. HTML files are sanitized
   with the same allowlist as compiled Markdown.

5. **Interactive artifact lane (Phase 5, not yet enabled)**: rich standalone
   HTML artifacts under `content/artifacts/` or `public/artifacts/` are loaded
   in sandboxed iframes (`sandbox="allow-same-origin"`). `allow-scripts` is
   explicitly prohibited without a security review.

## Rationale

- **Build-time compilation is correct for static export**: `output: "export"`
  means every page is pre-rendered at build time. Running Markdown compilation
  server-side at request time in `getStaticProps`-equivalent paths achieves
  nothing that build-time compilation does not; the runtime overhead is pure
  waste.
- **Explicit sanitization allowlist**: the only defence against content-injection
  attacks is an explicit allowlist of permitted HTML tags and attributes. Implicit
  trust of any Markdown-to-HTML output is unsafe.
- **`gray-matter` over hand-rolled parser**: eliminates a class of frontmatter
  edge-case bugs (multi-line values, YAML special characters, missing trailing
  newlines) at zero implementation cost.
- **`HtmlContent` as a single injection point**: concentrating `dangerouslySetInnerHTML`
  in one component with an enforced sanitizer dependency makes security audits
  and reviews tractable.
- **`MarkdownRenderer` / `react-markdown` removal**: reduces client bundle by
  removing parser dependencies that are no longer needed in the browser.

## Alternatives considered

- **MDX (`next-mdx-remote`)**: allows Markdown with embedded React components.
  Rejected for the main content path: MDX is more complex to sanitize, the
  existing content does not use React components in Markdown, and the
  `output: "export"` constraint requires careful MDX provider setup. May be
  reconsidered for a dedicated interactive docs lane.
- **Keep `react-markdown` but add `rehype-sanitize`**: partial improvement;
  does not eliminate the client-side runtime parsing overhead or the bundle
  bloat. Rejected.
- **Pre-compile at CI with a separate script**: content compilation outside the
  Next.js build pipeline complicates the `npm run build` flow and creates
  cache invalidation issues. Rejected in favour of integrating into `lib/content.ts`.

## Consequences

- **Positive**: Markdown parser dependencies (`react-markdown`, `next-mdx-remote`)
  removed from client bundle; hydration cost on content pages reduced.
- **Positive**: explicit HTML sanitization allowlist applied to all content;
  eliminates content-injection risk from Markdown raw HTML blocks.
- **Positive**: `gray-matter` frontmatter parser is robust against edge cases
  that broke the hand-rolled parser.
- **Positive**: docs and blog pages share a single `HtmlContent` / `ContentLayout`
  rendering path; locale and non-locale routes both go through the same pipeline.
- **Positive**: `content/docs/*.html` native pilot documents are supported;
  the architecture map and benchmark report artifacts are rendered in sandboxed
  iframes (`/[locale]/artifacts`).
- **Negative**: CSS-based styling (`.content-html` selector hierarchy) must
  precisely replicate the visual output of the component-based Markdown renderer.
  Visual regressions are possible during the switch.
- **Negative**: if the sanitizer allowlist is too strict, tables, diagrams, and
  code blocks may be stripped. Requires ongoing tuning as new content types
  are authored.
- **Risks / mitigations**: static export incompatibilities if `content.ts`
  accidentally imports a Node.js API not available in the Next.js static
  pipeline. Mitigated by `npm run build` in CI as the acceptance gate. Tests
  cover heading id generation, GFM tables, unsafe HTML stripping, and external
  link hardening (`tests/content.test.ts`).

## Implementation references

- Code: `shell-site/lib/content.ts` — content loading, frontmatter parsing,
  Markdown compilation, HTML sanitization, heading extraction
- Code: `shell-site/components/content/HtmlContent.tsx` — server-safe
  `dangerouslySetInnerHTML` wrapper
- Code: `shell-site/components/content/ContentLayout.tsx` — title/meta/tags/ToC
  wrappers shared by docs and blog
- Tests: `shell-site/tests/content.test.ts` — heading id, GFM table, unsafe
  HTML strip, external link hardening
- Content: `shell-site/content/docs/html-artifacts.html` — native HTML pilot doc
- Content: `shell-site/content/artifacts/architecture-map` and
  `benchmark-report` — sandboxed artifact examples
- Routes: `shell-site/app/[locale]/artifacts/[slug]/page.tsx` — sandboxed artifact lane
- Spec: session artefact `plan-md-html-refactor.md` — full 6-phase implementation
  plan, security policy, risk and rollout strategy

## Revisit triggers

- A future docs lane requires interactive React components embedded in Markdown
  (e.g., live code playgrounds); at that point MDX with a strict component
  allowlist should be reconsidered.
- The sanitizer allowlist is found to be insufficient for SVG diagrams embedded
  in content; a minimal safe SVG subset must be explicitly defined and added.
- `shell-site` migrates away from `output: "export"` to a server-rendered
  deployment; some build-time decisions (e.g., pre-compilation scope) may change.
- The interactive artifact lane (`/[locale]/artifacts`) needs `allow-scripts`
  for a specific use case; this requires a dedicated security review before the
  CSP policy is relaxed.
