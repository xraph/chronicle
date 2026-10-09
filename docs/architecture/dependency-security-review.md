# Documentation dependency security review

Reviewed 2026-10-09.

You can reproduce the patched docs tree with Node 22 and pnpm 10 using the committed manifest and lockfile. Next is pinned to 16.3.8, Fumadocs core/UI to 16.8.5 and MDX to 14.3.2. Direct PostCSS uses `^8.5.29`. React 19.2.4 and Tailwind 4.2.0 retain their existing versions and manifest ranges.

## Scope and dependency disposition

The complete GitHub inventory contained 95 open alerts: 60 lockfile records and 35 manifest records, representing 60 package/advisory identities. The baseline pnpm 10 audit exited 1 with 2 critical, 31 high, 25 moderate and 6 low findings. Counts reflect dependency paths and can differ from GitHub severity grouping.

These dependencies belong to the Next docs app, which runs App Router pages, server search, processed Markdown and Open Graph image routes. They are outside the Go service graph. We patched affected installed versions without assuming that an untested feature is safe.

| Package or chain | Execution and final disposition |
| --- | --- |
| Next | Development/production docs server and route generation: 16.3.8. |
| Next > sharp | Optional native image processing on build/server hosts: 0.35.5. |
| Next > baseline-browser-mapping | Build browser metadata: 2.11.28. |
| Next/Tailwind > PostCSS > source-map-js/nanoid | CSS parsing and source-map tooling: PostCSS 8.5.23 (Next), 8.5.29 (direct/Tailwind), source-map-js 1.2.2 and nanoid 3.3.20. |
| Fumadocs core/MDX > js-yaml | Content parsing: 4.3.2. |
| Fumadocs MDX > esbuild | Compilation/development tooling: 0.28.2. |
| Fumadocs MDX/globbing > picomatch | Content file matching: 4.0.7. |
| Fumadocs core > image-size/path-to-regexp | Image metadata/path compilation: both old packages removed. |
| Fumadocs UI > postcss-selector-parser | Selector compilation: old package removed. |

## Compatibility pin

The only override pins `mdast-util-to-markdown` to 2.1.2 across core, MDX and Markdown extensions. It is a compatibility pin with no known advisory suppression. Removing it resolved 2.2.0 and reproduced a production build failure with recursive strong/emphasis serialization and `Maximum call stack size exceeded`. Core 16.8.5 wraps Markdown handlers without retaining 2.2.0's attention metadata. Every parent accepts 2.1.2 through its 2.x range.

Remove this pin when core preserves handler metadata or replaces that stringifier, then pass frozen install, type generation, lint, full production build, Markdown HTTP checks and audit without the pin. The final build used a fresh generated cache after restoring the pinned graph.

## Verification and limits

Local checks used Node 22.23.3 and pnpm 10.31.0. From `docs/`, run:

```sh
corepack pnpm@10 install --frozen-lockfile
corepack pnpm@10 format package.json
corepack pnpm@10 types:check
corepack pnpm@10 lint
corepack pnpm@10 build
corepack pnpm@10 audit --json
```

The final frozen install, formatting, types, lint and production build passed. The final audit returned zero known vulnerabilities. Root `make l`, `make f` and `make l` passed; they check Go and do not replace docs checks. Database suites were outside this docs-only change. pnpm warned that esbuild's install script was ignored; MDX generation and the full build exercised the installed compiler successfully.

A local production server returned 200 for `/`, `/docs/getting-started`, `/api/search?query=audit`, `/llms-full.txt`, `/llms.mdx/docs/getting-started`, `/docs/getting-started.mdx` and `/og/docs/getting-started/image.png`. The `audit` search response parsed as JSON and returned documentation results. Markdown exports contained getting-started content, and the OG response had PNG content type and signature.

The page rendered at 1440x900 and 390x844 without horizontal document overflow. The browser reported a missing `/favicon.ico`; Next warned that metadataBase was unset. Neither prevented these checks.

The dormant `.github/workflows/docs-deploy.yml.txt` is not an enabled deployment workflow. Public deployment, cache topology, dev-server exposure and exploit reachability remain unverified. Local checks do not establish deployed security. GitHub reanalysis happens asynchronously after push, so you must inspect its refreshed alert inventory separately. No alerts were dismissed.
