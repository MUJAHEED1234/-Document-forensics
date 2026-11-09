# Synthetic demo dataset

These are generated, entirely fictional PDFs for exercising the prototype. They are not genuine identity documents and must never be used for real-world identity verification.

- `application_record.pdf` and `supporting_record.pdf` contain matching sample applicant details.
- `altered_supporting_record.pdf` changes the sample date of birth and uses a deliberately oversized font for that field. This should produce a cross-document field discrepancy and a visual font-size screening indicator. The prominent synthetic/demo disclaimer is preserved as a contextualized observation and excluded from the heuristic risk score when it is the only cited outlier.

Generate or refresh the PDFs from the project root:

```powershell
python backend\create_demo_dataset.py
python backend\create_demo_dossier.py
```

Upload the three PDFs as one investigation to demonstrate extraction, traceable field references, cross-document comparison, and highlighted visual screening. Font-size cues are screening observations only and do not prove manipulation; explicitly marked sample disclaimers are not counted as risk indicators.

The dossier command writes `sample_investigation_dossier.json` and `sample_investigation_dossier.pdf` from actual API processing in an isolated temporary workspace. The report's document IDs belong to that generated sample run; upload the PDFs in a live investigation to get IDs and previews in your local app.
