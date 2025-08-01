from fastapi import APIRouter, Depends, Request
from ..models import Principal
from ..security import get_principal

router = APIRouter(tags=["debug"])
@router.get("/whoami")
async def whoami(p: Principal = Depends(get_principal)):
    return p
@router.get("/echo-headers")
async def echo_headers(req: Request):
    return {"headers": dict(req.headers)}