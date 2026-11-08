# phishing-analyzer

A Python tool developed for **static analysis of email messeges in `.eml` format** to detect phishing. It reads the file as plain text only, extracts warning signs from it and produces a risk assesment together with an explanation

**Status:** work in progress; the remaining stages described below are planned (see [Roadmap](#roadmap)).

## Principles

- **Static and safe analysis.** The tool never opens, executes, or downloads anything and makes
no network connections. Links are not visited, attachments are neither saved to disk nor executed. Only the text message is analyzed.
- **Python standard library only** - nothing to install besides Python itself.
- **Explainability.** Every finding states *why* it was reported, not just a score.

## The way it works

The analysis runs as a pipeline, where each stage builds on the output of the previous one:

```
.eml file
   │
   ▼
[0] load             parse the file into a message object
   │
   ▼
[1] headers          From, Reply-To, Return-Path, SPF / DKIM / DMARC
   │
   ▼
[2] content          links and attachments
   │
   ▼
[3] risk rules       each rule returns a finding + points
   │
   ▼
[4] report           JSON or Markdown format
```

### 1. Headers: is the sender who they claim to be?

| Field | What is checked |
|---|---|
| `From` | sender domain shown to the user; the reference point for the other fields |
| `Reply-To` | whether replies would go to a different domain than `From` |
| `Return-Path` | whether the bounce address belongs to a different domain than `From` |
| `Authentication-Results` | results of the sender authentication checks performed by the receiving mail server: **SPF** (was the message sent from a server authorized by the domain?), **DKIM** (is the domain's cryptographic signature valid?), **DMARC** (do SPF/DKIM pass for the same domain as in From?). The tool only reads these results; it does not query DNS itself |

### 2. Links and attachments

- **Links:** mismatch between the link text and the actual URL, IP addresses instead of domain
names, URL shorteners, suspicious characters in the domain.
- **Atachments** (metadata only: name type, size): executable extensions, double extensions (e.g. `invoice.pdf.exe`), formats that may contain macros.

### 3. Risk rules

Each rule is a separate, independently tested function. It receives the data from
stages 1–2 and returns a finding, for example:

```json
{"rule": "reply_to_mismatch", "score": 20, "detail": "Reply-To: x@other.invalid ≠ From: bank.invalid"}
```

Points are summed into an overall risk level. Data extraction (stages 1–2) is separated
from evaluation (stage 3), so rules and scoring can be changed without touching the parsers.

### 4. Report

The analysis result in two formats: **JSON** for further processing
and **Markdown** for human readers.

## Project structure

```
analyzer/   analyzer source code
samples/    fictional .eml samples (.invalid domains only)
tests/      unit tests (unittest)
```

All samples in `samples/` are made up and use the reserved `.invalid` top-level domain
(RFC 2606), so they never point to real addresses.

## Usage

Requires Python 3.10+.

```bash
python -m analyzer.loader samples/sample_01.eml
```

Example output:

```
From:    Bank Support <support@secure-bank.invalid>
Subject: Pilne: potwierdź swoje konto
```

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## Roadmap

- [x] Loading `.eml` files
- [ ] Stage 1: header analysis (From, Reply-To, Return-Path, SPF/DKIM/DMARC)
- [ ] Stage 2: link and attachment analysis
- [ ] Stage 3: risk rules and scoring
- [ ] Stage 4: JSON / Markdown report
