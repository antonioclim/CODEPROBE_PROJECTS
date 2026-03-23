# Contributing

Thank you for considering a contribution to CodeProbe.

## Scope

This project is a browser-based heuristic static analysis tool intended for teaching use. Contributions should improve correctness, clarity, robustness, documentation or pedagogy without breaking the transparent architecture:

- `src/index.html` provides the browser interface and JavaScript application layer
- `src/engine.py` provides the Python analysis engine executed through Pyodide
- course-facing documents in the repository root describe recommended academic use

## Before you open a pull request

1. read the current `README.md` and `CHANGELOG.md`
2. keep user-facing text in British English
3. preserve backward compatibility for Python, JavaScript and Bash analysis
4. avoid adding non-standard Python dependencies to the engine
5. keep the browser delivery static and transparent

## Coding expectations

### Python engine

- use only the Python standard library
- preserve the metric registry architecture
- add references for new metrics where appropriate
- keep comments and report text concise and academically toned
- prefer small, testable helper functions over large monolithic additions

### Browser interface

- keep the dark theme, layout grid and responsive behaviour coherent
- avoid introducing external dependencies beyond Pyodide
- keep language labels, status text and help text in British English
- do not reintroduce Base64-packed execution patterns for the engine

## Recommended validation before submission

1. run `python3 -m py_compile src/engine.py`
2. launch `python3 src/run_local_server.py`
3. test the analysis flow with at least one file in each supported language family you touched
4. confirm that export, history and metric rendering still work
5. verify that the **Course use policy** panel remains visible and accurate

## Commit and pull request style

- use clear commit messages in the imperative mood
- keep pull requests focused on one topic where possible
- describe user-visible changes and any analysis limitations
- mention affected languages or metrics explicitly
- update `CHANGELOG.md` when the change is release-relevant

## Documentation changes

If you change thresholds, policies or supported languages, update the following files together where relevant:

- `README.md`
- `COURSE_INTEGRATION.md`
- `PROJECT_KIT_NOTICE.md`
- `STUDENT_DISCLOSURE_TEMPLATE.md`

## Security and privacy notes

Please avoid changes that would send analysed source code to remote services. The tool is intended to keep inspected code local to the student's machine, apart from fetching the Pyodide runtime from its CDN.
