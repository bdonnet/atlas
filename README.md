# ATLAS — Authentication TechnoLogy AnalysiS

ATLAS is a large-scale web measurement tool designed to automatically detect and classify the authentication mechanisms used by websites (e.g., password-only, password + OTP, FIDO2/Passkey). It combines browser automation, DOM analysis, network interception, and heuristic classification to infer authentication signals at scale.

ATLAS is the artifact accompanying the paper:

> **Highway to Auth: A Large-Scale Measurement of Web Authentication Signals with ATLAS**
> *(Under submission — double-blind peer review)*

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Code Architecture](#code-architecture)
3. [Installation](#installation)
4. [Usage](#usage)
   - [SCRAPING](#scraping)
   - [CHALLENGE](#challenge)
   - [ANALYSIS](#analysis)
5. [Directory Layout](#directory-layout)
6. [Contributors](#contributors)
7. [Funding](#funding)

---

## Project Structure

```
.
├── src/                  # All Python source code
│   ├── main.py               # Entry point — run any experiment from here
│   ├── import_data.py        # Centralised imports for the entire project
│   ├── logger.py             # Logging configuration
│   ├── utils.py              # Shared utility functions
│   ├── configs/              # Project-wide constants and configuration
│   ├── atlas/                # Core scraper
│   ├── challenge/            # FIDO2 cryptographic challenge capture
│   └── analysis/             # Post-processing and data analysis
├── CSV/                  # Input URL lists and output CSV results
├── Logs/                 # Execution logs
├── Plots/                # Pandas DataFrame dumps (CSV) for figures
└── Screenshots/          # Login-page screenshots (gzip archives)
```

---

## Code Architecture

### `configs/`

Contains all Python files declaring project-wide constants. Every constant is documented inline in its respective file. The configuration files cover the following concerns:

- `agents.py` — User-agent strings used during scraping
- `cose.py` — COSE algorithm identifiers (used for FIDO2 challenge analysis)
- `fido_keywords.py` — Keywords used to detect FIDO2-related signals during analysis
- `keywords.py` — General keywords used during scraping (login-page detection, etc.)
- `output_csv.py` — Column definitions for output CSV files
- `paths.py` — All file-system paths (input datasets, output files, directories)
- `patterns.py` — Regular-expression patterns used during scraping
- `selectors.py` — CSS/XPath selectors used during DOM analysis
- `signals.py` — Authentication signal definitions captured by the scraper
- `timeouts.py` — Timeout values for browser interactions

### `atlas/`

The core ATLAS scraper (described in **Section 4** of the paper). It takes a list of URLs as input (CSV format) and produces a CSV file containing all signals required for post-processing analysis. Each function in every module is documented. Key modules include:

- `Atlas.py` — Top-level orchestration: runs the scraping pipeline over the input dataset
- `ProcessSite.py` — Per-site processing logic
- `Authentication.py` — Authentication signal extraction
- `Classification.py` — Heuristic classification of the authentication mechanism
- `ConfidenceScore.py` — Confidence scoring for the inferred classification
- `Dom.py` — DOM parsing and element extraction
- `ShadowDom.py` — Shadow DOM traversal (open and closed)
- `IFrameHandler.py` — iframe detection and navigation
- `Interaction.py` — Browser interaction logic (clicks, form filling, etc.)
- `MultiStepLogin.py` — Multi-step / split login-flow detection
- `NetworkAnalyser.py` — Network request/response interception and analysis
- `LocalStorageAnalyser.py` — Local storage inspection
- `OTPDetection.py` — OTP field detection
- `PasskeyTrigger.py` — Passkey / FIDO2 trigger detection
- `FedCMDetector.py` — Federated Credential Management (FedCM) detection
- `CookieBanner.py` — Cookie-banner detection and dismissal
- `PageContextClassifier.py` — Page-context classification (login page vs. other)

### `challenge/`

An adaptation of the ATLAS scraper dedicated to capturing the cryptographic challenge exchanged during a FIDO2 authentication ceremony (described in **Section 7** of the paper). It targets sites previously classified as FIDO2 by the main scraper. Key modules include:

- `RunChallengeCapture.py` — Orchestrates the challenge capture pipeline
- `ChallengeCaptureSite.py` — Per-site challenge capture logic
- `AnalyseFidoChallenge.py` — Parsing and analysis of captured challenges
- `ChallengeUtils.py` — Utility functions for challenge processing

### `analysis/`

Post-processing and statistical analysis of the data collected by the scraper and the challenge module (results presented in **Sections 5, 6, and 7** of the paper). Key modules include:

- `AnalyseAtlas.py` — Top-level analysis dispatcher
- `GroundtruthAnalysis.py` — Ground-truth evaluation (Section 5)
- `ScrapingAnalysis.py` — Large-scale scraping analysis (Section 6)
- `ChallengeCaptureAnalysis.py` — FIDO2 challenge analysis (Section 7)
- `EthicsAnalysis.py` — Ethical considerations analysis
- `Filtering.py` — Dataset filtering logic
- `URLFiltering.py` — URL-level filtering
- `ClosedShadowDOMValidator.py` — Validation of closed Shadow DOM detection
- `StatsUtils.py` — Statistical utility functions (e.g., Fisher's exact test)
- `ForestPlot.py` — Forest plot data preparation

> **Note on plotting:** The matplotlib/seaborn plotting calls have been removed from this codebase, as they rely on a local wrapper library. The `analysis/` modules instead produce CSV dumps of the relevant Pandas DataFrames into `Plots/`, which were used as input to the figure-generation pipeline.

---

## Installation

### Prerequisites

- Python 3.10+
- [Playwright](https://playwright.dev/python/) browsers installed

### Steps

```bash
# 1. Clone the repository
git clone <repository_url>
cd <repository_directory>

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Playwright browser binaries
playwright install
```

---

## Usage

All experiments are launched through `main.py`:

```
python main.py <EXPERIMENT> <PARAMETERS>
```

where `<EXPERIMENT>` is one of: `SCRAPING`, `CHALLENGE`, `ANALYSIS`.

---

### SCRAPING

Runs the core ATLAS scraper to infer the authentication mechanism of a list of websites. Input files (CSV) are located in `CSV/URLs/`.

```bash
python main.py SCRAPING -i <input>
```

| `<input>` value | Description |
|---|---|
| `TEST` | A small set of websites for testing purposes |
| `GROUNDTRUTH` | Launches ATLAS on the ground-truth dataset (see Section 5) |
| `DATASET_0` | Sub-part 0 of the Top 1M URL dataset |
| `DATASET_1` | Sub-part 1 of the Top 1M URL dataset |
| `DATASET_2` | Sub-part 2 of the Top 1M URL dataset |
| `DATASET_3` | Sub-part 3 of the Top 1M URL dataset |

The dataset is split into four parts (`DATASET_0` to `DATASET_3`) to allow simultaneous execution across four machines, each running its own multi-process instance of ATLAS.

**Optional arguments:**

| Flag | Description |
|---|---|
| `-r` / `--resume` | Resume scraping after a failure |
| `-d` / `--dump_every <N>` | Dump results to CSV every N sites (default: 500) |
| `-p` / `--parallel <N>` | Number of parallel processes |

**Example:**
```bash
python main.py SCRAPING -i TEST
python main.py SCRAPING -i DATASET_0 -r -d 200 -p 4
```

---

### CHALLENGE

Captures the cryptographic FIDO2 challenge for sites previously classified as FIDO2 by the scraper. Input files (CSV) are located in `CSV/Challenge/`.

```bash
python main.py CHALLENGE -i <input>
```

| `<input>` value | Description |
|---|---|
| `TEST` | A small set of websites for testing purposes |
| `FIDO2` | Sites identified as FIDO2 during the SCRAPING phase |

**Optional arguments:**

| Flag | Description |
|---|---|
| `-r` / `--resume` | Resume capture after a failure |
| `-d` / `--dump_every <N>` | Dump results to CSV every N sites (default: 500) |

**Example:**
```bash
python main.py CHALLENGE -i TEST
python main.py CHALLENGE -i FIDO2 -r
```

---

### ANALYSIS

Performs post-processing analysis on the collected data. This command produces CSV dumps of Pandas DataFrames (written to `Plots/`) and prints statistical results. No figures are generated directly.  Note that some input files have been gzipped due to GIT requirements.  Those files must be locally ungzipped prior to any analysis.

```bash
python main.py ANALYSIS -m <metric>
```

| `<metric>` value | Description |
|---|---|
| `ETHICS` | Generates data for the two Ethical Considerations plots |
| `GROUNDTRUTH` | Full ground-truth analysis (Section 5) |
| `SCRAPING` | Full large-scale scraping analysis — Top 1M (Section 6) |
| `CHALLENGE` | Full FIDO2 cryptographic challenge analysis (Section 7) |

**Example:**
```bash
python main.py ANALYSIS -m GROUNDTRUTH
python main.py ANALYSIS -m SCRAPING
```

---

## Directory Layout

In addition to the source code, the project relies on the following directories (not included in this repository):

| Directory | Description |
|---|---|
| `CSV/URLs/` | Input CSV files containing URL lists for scraping |
| `CSV/Groundtruth/` | Ground-truth dataset and scraping results |
| `CSV/Scraping/` | Output CSV files produced by the SCRAPING phase |
| `CSV/Challenge/` | Output CSV files produced by the CHALLENGE phase |
| `Logs/` | Log files generated at each execution of `main.py` (written in French) |
| `Plots/` | CSV dumps of Pandas DataFrames used as input for figure generation |
| `Screenshots/` | Screenshots of detected login pages, archived on-the-fly into gzip files |

---

## Contributors

Anonymous for double-blind reasons.

---

## Funding

Hidden for double-blind reasons.
