from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List

from file_handler import handle_uploaded_file
from parser import parse_rules

router = APIRouter()


@router.post("/upload")
async def upload_file(files: List[UploadFile] = File(...)):
    """
    Upload one or more firewall config files (.csv, .json, .txt).
    Rules extracted from each file are automatically parsed and audited.
    """
    results = []
    for uploaded_file in files:
        filename = uploaded_file.filename
        content = await uploaded_file.read()
        try:
            rules = handle_uploaded_file(filename, content)
            parsed = parse_rules(rules)
            success = sum(1 for r in parsed if not r.get("error"))
            results.append({
                "filename": filename,
                "status": "success",
                "total_rules": len(parsed),
                "parsed_successfully": success,
                "failed_to_parse": len(parsed) - success,
                "results": parsed,
            })
        except ValueError as exc:
            results.append({"filename": filename, "status": "error", "error": str(exc)})
        except Exception as exc:
            results.append({"filename": filename, "status": "error", "error": f"Unexpected error: {exc}"})
    return {
        "status": "success",
        "data": {
            "files": results,
            "total_files": len(results),
        },
        # Keep legacy key for older clients.
        "results": results,
    }
