RISK_ANALYSIS_PROMPT = """Analyze only the provided static-scan finding and evidence. Return validated structured risk analysis."""
FALSE_POSITIVE_PROMPT = """Review whether the finding may be a false positive using only evidence and scanner metadata."""
FIX_SUGGEST_PROMPT = """Suggest a safe remediation without modifying user code automatically."""
