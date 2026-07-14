from fastapi import APIRouter, Depends

from auth.jwt import current_user
from db.repository import find_user

router = APIRouter(prefix="/users")


@router.get("/{name}")
def get_user(name: str, user=Depends(current_user)):
    return find_user(name)
