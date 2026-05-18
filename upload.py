from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List
import csv
import json
from .file_handler import handle_uploaded_file

router = APIRouter()

@router.post("/upload")
async def upload_file(files: List[UploadFile] = File(...)):
    results = []
    for uploaded_file in files:
        filename = uploaded_file.filename
        content = await uploaded_file.read()
        try:
            result = handle_uploaded_file(filename, content)
            results.append({"filename": filename, "status": "success", "data": result})
        except Exception as e:
            results.append({"filename": filename, "status": "error", "error": str(e)})
    return {"results": results}
