from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

app = FastAPI()

# CORS middleware (important for frontend communication)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this for production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Item(BaseModel):
    name: str
    value: int

items_db = [     # SQLite would be better, but this is quick
    {"name": "Item 1", "value": 10},
    {"name": "Item 2", "value": 20},
]

@app.get("/api/items")
async def get_items():
    return items_db

@app.post("/api/items")
async def create_item(item: Item):
    items_db.append(item.model_dump())
    return {"message": "Item created", "item": item}

# Mount the MkDocs static site
import os
os.system("mkdocs build")
app.mount("/", StaticFiles(directory="site", html=True), name="site")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000,
                ssl_keyfile="key.pem", 
                ssl_certfile="cert.pem")