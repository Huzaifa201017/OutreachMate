from typing import Annotated
from fastapi import Depends, FastAPI
from auth import get_current_user, router
import models
from database import engine
from starlette import status
from dependencies import db_dependency

app = FastAPI()

app.include_router(router)

models.Base.metadata.create_all(bind=engine)


user_dependency = Annotated[dict, Depends(get_current_user)]


@app.get("/", status_code=status.HTTP_200_OK)
async def user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed")
    return {"User": user}
