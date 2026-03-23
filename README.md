# CodeProbe v2 — transparent browser kit

CodeProbe v2 is a browser-based heuristic static analysis workbench for source code and technical Markdown. It runs entirely on the client side through Pyodide, keeps the Python engine readable as a separate file and avoids the Base64-packed single-file delivery model that often triggers antivirus heuristics.

This repository contains the transparent edition prepared for local use, GitHub publication and static hosting.

## What this kit provides

CodeProbe combines a dark-theme browser interface with a registry-based Python analysis engine. The current kit supports Python, JavaScript, Bash, C, C++, C# and Markdown. It produces a summary view, per-metric detail, a plain-text report, a JSON report and a small local history in the browser.

The analysis is heuristic by design. It is useful for teaching, exploratory quality assessment and comparative inspection of code samples. It is not a compiler, a security scanner or a proof of authorship.

## Why this transparent edition exists

The original single-file packaging model embedded the Python engine inside HTML as a large Base64 payload and reconstructed it at run time. That design is portable, but it resembles delivery patterns used by HTML smuggling and other browser-side payload loaders. Some antivirus products therefore flag it even when the code itself is benign.

This edition removes that packaging pattern. The browser now loads a plain `engine.py` file directly. That change improves inspectability and usually reduces false-positive malware detections.

## Key features

- Local-first analysis in the browser through Pyodide
- Readable Python engine in `engine.py`
- No Base64-packed analysis engine
- Support for Python, JavaScript, Bash, C, C++, C# and Markdown
- Core stylistic and structural metrics across languages
- Low-level quality metrics for C, C++ and partly C#
- Reduced prose-aware metric set for Markdown
- JSON and text export
- Local report history stored in browser storage only
- Drag-and-drop file loading, syntax highlighting and language auto-detection

## Repository layout

```text
.
├── index.html
├── engine.py
├── run_local_server.py
├── README.md
└── README.txt
```

## Requirements

| Component | Requirement |
|---|---|
| Browser | A modern Chromium, Firefox or Safari-class browser |
| Network | Internet access to load Pyodide from the official CDN |
| Python | Optional, only if you want to use `run_local_server.py` |

No build step is required.

## Quick start

### Recommended launch

Keep `index.html` and `engine.py` in the same directory, then run:

```bash
python run_local_server.py
```

Open the address printed in the terminal. The helper server binds to `127.0.0.1` on a free local port.

### Direct opening from the file system

You can also open `index.html` directly. Some browsers block relative file loading for local files. If that happens, use the **Load engine file** button and select `engine.py` manually.

### GitHub and GitHub Pages

For a normal repository, place `README.md` at the repository root together with `index.html` and `engine.py`.

For GitHub Pages, keep `index.html` and `engine.py` in the published directory. Because the engine is fetched as a normal file over HTTP, the helper server is not needed once the site is hosted.

## Supported languages

| Language | Extensions | Detection signals | Notes |
|---|---|---|---|
| Python | `.py`, `.pyw` | extension, shebang, syntax cues | Uses `ast` where suitable |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` | extension, shebang, syntax cues | Includes modern syntax checks |
| Bash | `.sh`, `.bash`, `.zsh`, `.ksh` | extension, shebang, shell syntax | Includes quoting consistency checks |
| C | `.c`, `.h` | extension, preprocessor and brace cues | Includes low-level quality metrics |
| C++ | `.cpp`, `.cxx`, `.cc`, `.hpp`, `.hxx`, `.hh` | extension, templates, namespaces and brace cues | Includes low-level quality metrics |
| C# | `.cs` | extension, `using`, attributes and brace cues | Includes transferable low-level metrics |
| Markdown | `.md`, `.markdown` | extension, heading and fence cues | Uses a reduced prose-oriented metric set |

## Metric coverage

The engine currently provides more than thirty metrics organised into four broad groups.

### 1. Cross-language code metrics

These include line-length uniformity, blank-line regularity, lexical entropy, identifier style, function length, cyclomatic complexity, Halstead difficulty, magic-number density, nesting depth, defensive programming, indentation consistency, structural self-similarity and related measures.

### 2. Language-specific metrics

These include Python docstring coverage, Python type-hint coverage, JavaScript modern syntax, Bash variable-quoting consistency and import organisation.

### 3. Low-level quality metrics

For C and C++ the engine adds:

- register pressure estimation
- stack frame depth estimation
- redundant memory access patterns
- code elegance composite
- preprocessor hygiene

For C# the transferable subset is enabled where the heuristics remain meaningful.

### 4. Markdown metrics

Markdown analysis uses a narrower set:

- heading-structure regularity
- code-fence density
- link density
- prose entropy

Comment-to-code ratio is intentionally not applied to Markdown.

## What the interface shows

The right-hand analysis panel contains four result views and one local history view.

| Panel | Purpose |
|---|---|
| Summary | High-level verdict, aggregate score, warnings and references |
| Metrics | Per-metric values, scores, explanations and notes |
| Text report | Human-readable narrative report |
| JSON | Machine-readable report payload |
| History | Recent local analyses stored in browser storage |

For C, C++ and C# an additional **Low-Level Quality** summary card is shown.

## Privacy and data handling

CodeProbe analyses source text in the browser. The code being inspected is not uploaded by this kit to a remote service. The application stores only a short local history in browser storage so that recent reports can be reopened.

The only required network dependency is the Pyodide runtime loaded from the official CDN.

## Interpretation and limitations

- The engine is heuristic. It estimates patterns from source text and does not replace a compiler, a profiler or a formal static analyser.
- C, C++ and C# low-level metrics are source-level approximations. They do not observe actual register allocation, generated stack frames or emitted assembly.
- Markdown analysis is intentionally narrower than code analysis.
- The verdict layer should be read as a probabilistic signal about stylistic regularity and scaffold-like structure, not as evidence of misconduct.
- Small files, generated boilerplate and highly stylised teaching examples can distort metric values.

## Typical workflow

1. Open the interface.
2. Paste code, drop a file or load a source file from disk.
3. Leave language on **Auto** or select a language explicitly.
4. Choose a scoring profile if needed.
5. Run **Analyse**.
6. Inspect the summary card, detailed metrics and exported report.

## Development notes

The project keeps the existing browser architecture intact:

- `index.html` contains the interface and application logic
- `engine.py` contains the registry-based Python engine
- Pyodide runs the engine in the browser
- exports are generated locally in the client

This makes the package easy to audit and easy to adapt for teaching or demonstration purposes.

## Suggested repository extras

For a public GitHub repository, it is sensible to add the following files if you want a more polished project page:

- `LICENSE`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- a screenshot placed in `docs/` or `assets/`

## Selected references

Buse, R. P. L., & Weimer, W. R. (2008). *A metric for software readability*. Proceedings of the 2008 International Symposium on Software Testing and Analysis, 121–130. https://doi.org/10.1145/1390630.1390647

Chaitin, G. J. (1982). *Register allocation and spilling via graph coloring*. ACM SIGPLAN Notices, 17(6), 98–105. https://doi.org/10.1145/872726.806984

McCabe, T. J. (1976). *A complexity measure*. IEEE Transactions on Software Engineering, SE-2(4), 308–320. https://doi.org/10.1109/TSE.1976.233837

Poletto, M., & Sarkar, V. (1999). *Linear scan register allocation*. ACM Transactions on Programming Languages and Systems, 21(5), 895–913. https://doi.org/10.1145/330249.330250
