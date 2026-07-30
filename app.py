# OrderFlow — Main Application
# Starter file for Section 1: API Authentication & Security
#
# The app currently exposes two routes with no authentication or CORS.
# Your tasks:
#   1. Configure CORS middleware to allow requests from the React frontend
#   2. Protect GET /products using the JWT auth dependency from auth.py

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from auth import router as auth_router, get_current_user, User

app = FastAPI(title="OrderFlow API — L2")

# TODO 1 — Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Auth Router
app.include_router(auth_router)


# Sample data (do not modify)

PRODUCTS = [
    {"product_id": 1, "name": "Laptop",   "price": 999.99},
    {"product_id": 2, "name": "Keyboard", "price":  49.99},
    {"product_id": 3, "name": "Monitor",  "price": 299.99},
]


class OrderRequest(BaseModel):
    product_id: int
    quantity: int


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/products")
def get_products(current_user: User = Depends(get_current_user)):
    return PRODUCTS


@app.post("/orders", status_code=201)
def create_order(order: OrderRequest):
    # Public endpoint — no auth required
    return {
        "message": f"Order placed for product {order.product_id}",
        "quantity": order.quantity,
    }

