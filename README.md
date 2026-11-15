# A3-PS013-TC089: Vigilance, Incident Timeline and Evidence Collection

**Problem Statement ID:** PS-013  
**Category:** Cyber Security  
**Event:** AIORI Hackathon 3  
**Team Code:** A3-PS013-TC089

---

## Team Introduction Video

[Watch our Team Introduction & Problem Overview on YouTube](https://youtu.be/wswCH0Zga0A)

---
## Project Demonstration

**Vigilance - Incident Timeline and Evidence Collection**

Watch our complete project demonstration: [Vigilance Demo Video](https://youtu.be/rezQo_kvrec?si=gAwsindLj3jWXrqa)
---

## Team and Mentorship Structure

### Faculty Project Guide
- **Dr. Vrushali Waghmare**: Project Mentor & Academic Guide

### Student Team Members
- **Anay Deshmukh**: Problem Analysis, Technical Research & Solution Planning
- **Rushikesh Chavan**: Solution Design, Workflow Planning & Evaluation

---

## Problem Statement

Cybersecurity investigations require analyzing logs from different systems and applications. Differences in log formats, timestamps, and system clock settings make it difficult to reconstruct the sequence of events efficiently. Manual analysis is time-consuming, evidence integrity must be maintained, and malformed or unsupported records may be overlooked.


## Proposed Solution: Vigilance

Vigilance is a proposed lightweight digital forensic tool that combines logs from multiple sources into a searchable chronological incident timeline. It aims to preserve original log files, generate SHA-256 hashes, normalize timestamps to UTC where possible, identify parsing gaps and timestamp uncertainty, and generate incident reports to support more efficient and structured investigations.

https://vigilance-cz0a.onrender.com/

The ingestion workflow also supports an explicit **reference year** for syslog sources that omit the year, and an investigator-supplied **clock-skew offset** in seconds. Adjusted timestamps retain their original values and are marked `CLOCK_SKEW_ADJUSTED` so the correction remains auditable rather than silent.

### Large Log Handling

Uploads are streamed to disk in 1 MB chunks and hashed incrementally, so the full artifact is never held in memory. Parsing runs as a background job and the UI polls `/api/processing-jobs/{job_id}` for progress. Syslog, CSV, and NDJSON are parsed line-by-line; JSON arrays still require a full decode. Events are persisted in bounded batches controlled by `INGESTION_BATCH_SIZE` (default `50000`).

A 70 MB `SSH.log` with 655,147 syslog lines was tested at roughly **197 MB peak RSS** with this path, versus ~2.5 GB for the previous all-in-memory implementation. A full HTTP upload of the same file completed in **134 seconds** inside a **512 MiB container**, with Docker reporting about **316 MiB** memory use. The original file remains sealed and downloadable for integrity verification after processing.

Storage is the main deployment constraint: this test produced a **~715 MB SQLite database**, a transient **~117 MB WAL file**, and **~71 MB** of sealed evidence. Ensure the host has enough disk for the expected evidence volume, or reduce `INGESTION_BATCH_SIZE`/retention for smaller environments.
