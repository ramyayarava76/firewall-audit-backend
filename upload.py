from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List

from file_handler import handle_uploaded_file
from parser import parse_rules
from logger import get_logger, RequestLogger, TaskLogger

logger = get_logger(__name__)

router = APIRouter()


@router.post("/upload")
async def upload_file(files: List[UploadFile] = File(...)):
    """
    Upload one or more firewall config files (.csv, .json, .txt).
    Rules extracted from each file are automatically parsed and audited.
    """
    logger.info(f"File upload initiated with {len(files)} file(s)")
    TaskLogger.log_task_start("file_upload", {"file_count": len(files)})
    
    results = []
    for uploaded_file in files:
        filename = uploaded_file.filename
        logger.info(f"Processing uploaded file: {filename}")
        content = await uploaded_file.read()
        try:
            rules = handle_uploaded_file(filename, content)
            logger.debug(f"Extracted {len(rules)} rules from {filename}")
            parsed = parse_rules(rules)
            success = sum(1 for r in parsed if not r.get("error"))
            logger.info(f"File {filename}: {success}/{len(parsed)} rules parsed successfully")
            results.append({
                "filename": filename,
                "status": "success",
                "total_rules": len(parsed),
                "parsed_successfully": success,
                "failed_to_parse": len(parsed) - success,
                "results": parsed,
            })
        except ValueError as exc:
            logger.warning(f"ValueError processing {filename}: {exc}")
            results.append({"filename": filename, "status": "error", "error": str(exc)})
        except Exception as exc:
            logger.error(f"Unexpected error processing {filename}: {exc}", exc_info=True)
            results.append({"filename": filename, "status": "error", "error": f"Unexpected error: {exc}"})
    
    successful_uploads = sum(1 for r in results if r["status"] == "success")
    logger.info(f"Upload completed: {successful_uploads}/{len(results)} files processed successfully")
    TaskLogger.log_task_complete("file_upload", {"successful_files": successful_uploads})
    RequestLogger.log_request("POST", "/api/v1/upload", 200, details={"files_uploaded": successful_uploads})
    
    return {
        "status": "success",
        "data": {
            "files": results,
            "total_files": len(results),
        },
        # Keep legacy key for older clients.
        "results": results,
    }
