from fastapi import APIRouter, UploadFile

router = APIRouter(prefix="/files")


@router.post("/upload")
def upload_file(file: UploadFile):
    return {"filename": file.filename}
