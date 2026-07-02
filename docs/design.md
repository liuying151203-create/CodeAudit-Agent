# Design

CodeAudit-Agent separates deterministic detection from reasoning. Scanners find concrete risky patterns, and the Agent only analyzes those candidates with local evidence. This reduces hallucination, keeps execution safe, and makes reports reproducible.

The MVP avoids executing audited code. It only reads files and Git diff text.
