from fastapi import FastAPI
from auth.router import router
import models
from database import engine

app = FastAPI()

models.Base.metadata.create_all(bind=engine)

app.include_router(router)
