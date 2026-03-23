# Course integration guide for CodeProbe v2

This note is intended for lecturers who want to place the CodeProbe kit inside project folders for other modules.

## Recommended position

Use CodeProbe as a **formative self-check** and a **triage signal for review**, not as an automatic decision system.

A defensible teaching position is:

- students run the tool locally before submission
- only student-authored source files are checked
- a score above **60%** triggers revision and disclosure, not immediate sanction
- any final concern is reviewed alongside Git history, project notes and an oral code explanation

## Why this position is preferable

The engine uses stylometric and structural heuristics. Such heuristics can be informative, but they do not amount to direct proof of authorship or misconduct. False positives and false negatives remain possible, especially with small files, heavily scaffolded assignments or code rewritten after external assistance.

## Suggested threshold bands

| Score band | Interpretation | Instructor action |
|---|---|---|
| 0–50% | Low concern | No special action |
| >50–60% | Borderline | Ask for self-review if needed |
| >60–75% | Elevated | Require revision and a brief disclosure |
| >75% | High | Review manually with Git history and oral walkthrough |

## Suggested wording for a syllabus or assignment brief

> Students must run the bundled CodeProbe kit locally on the code they authored for the project before submission. The reported AI-assistance suspicion score is a formative signal, not proof of misconduct. A result above 60% requires code revision and, where requested, a short disclosure describing any AI assistance, what was retained, what was rewritten and how correctness was validated. Final academic judgement, where needed, will be based on the CodeProbe report together with repository history, intermediate commits, design notes and an oral code walkthrough. Starter code, third-party libraries, generated files, minified assets and documentation must be excluded from the check.

## Suggested student workflow

1. run CodeProbe on authored files only
2. inspect the score, warnings and metric detail
3. if the result is above 60%, revise the code and re-run the analysis
4. export the report if the module requires it
5. complete the bundled disclosure template if AI tools were used

## Suggested instructor workflow

1. publish the kit inside a dedicated `codeprobe/` folder in the project repository
2. keep the application files inside `codeprobe/src/`
3. keep screenshots and support media inside `codeprobe/docs/`
4. include `PROJECT_KIT_NOTICE.md` or adapt it for the assignment brief
5. make clear that the tool is a self-check, not a disciplinary engine
6. require students to exclude third-party and generated material
7. use manual review only for elevated or persistently high scores
8. confirm concerns through repository history and code explanation

## Evidence model for manual review

A proportionate review normally combines:

- the CodeProbe report
- repository history and intermediate commits
- a brief note describing any AI assistance
- a short oral walkthrough focused on the submitted code

This combination is much stronger than relying on a single score.

## What not to do

- do not run the tool on entire repositories by default
- do not include vendor code, starter code or generated files
- do not treat a score threshold as self-sufficient evidence
- do not assume that a low score proves independent work

## Minimal repository layout

```text
project-root/
├── codeprobe/
│   ├── .codeprobeignore.example
│   ├── COURSE_INTEGRATION.md
│   ├── PROJECT_KIT_NOTICE.md
│   ├── README.md
│   ├── STUDENT_DISCLOSURE_TEMPLATE.md
│   ├── docs/
│   │   └── codeprobe-interface-preview.png
│   └── src/
│       ├── engine.py
│       ├── index.html
│       └── run_local_server.py
├── src/
└── README.md
```

## Academic background

| APA 7 reference | DOI |
|---|---|
| Dalalah, D., & Dalalah, O. M. A. (2023). The false positives and false negatives of generative AI detection tools in education and academic research: The case of ChatGPT. *The International Journal of Management Education, 21*(2), 100822. | https://doi.org/10.1016/j.ijme.2023.100822 |
| Krsul, I., & Spafford, E. H. (1997). Authorship analysis: identifying the author of a program. *Computers & Security, 16*(3), 233–257. | https://doi.org/10.1016/S0167-4048(97)00005-9 |
| Nicol, D. J., & Macfarlane-Dick, D. (2006). Formative assessment and self-regulated learning: A model and seven principles of good feedback practice. *Studies in Higher Education, 31*(2), 199–218. | https://doi.org/10.1080/03075070600572090 |
| Wang, H., Dang, A., Wu, Z., & Mac, S. (2024). Generative AI in higher education: Seeing ChatGPT through universities’ policies, resources and guidelines. *Computers & Education: Artificial Intelligence, 7*, 100326. | https://doi.org/10.1016/j.caeai.2024.100326 |
