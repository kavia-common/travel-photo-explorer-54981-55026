import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, status, Query, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from uuid import uuid4

# Load environment variables for configuration (e.g., UNSPLASH access key)
load_dotenv()

# --------------------------------------------------------------------------------------
# In-memory persistence (for demo purposes)
# --------------------------------------------------------------------------------------
# NOTE: This backend uses in-memory stores to avoid DB complexity for the task.
# A production system should replace these with a proper database.
USERS: Dict[str, Dict[str, Any]] = {}           # key: user_id
USERS_BY_EMAIL: Dict[str, str] = {}             # key: email -> user_id
TOKENS: Dict[str, Dict[str, Any]] = {}          # key: token -> { user_id, exp }
PHOTOS: Dict[str, Dict[str, Any]] = {}          # key: photo_id

# --------------------------------------------------------------------------------------
# Security helpers (simple bearer tokens for demo)
# --------------------------------------------------------------------------------------
security = HTTPBearer()

TOKEN_TTL_MINUTES = int(os.getenv("TOKEN_TTL_MINUTES", "120"))

def _now_utc() -> datetime:
    return datetime.utcnow()

def _generate_token(user_id: str) -> str:
    token = str(uuid4())
    TOKENS[token] = {"user_id": user_id, "exp": _now_utc() + timedelta(minutes=TOKEN_TTL_MINUTES)}
    return token

def _validate_token(token: str) -> str:
    info = TOKENS.get(token)
    if not info:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    if info["exp"] < _now_utc():
        # Expired token, revoke
        TOKENS.pop(token, None)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    return info["user_id"]

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """
    Dependency that validates Authorization: Bearer <token> and returns user object.
    """
    token = credentials.credentials
    user_id = _validate_token(token)
    user = USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown user")
    return user

# --------------------------------------------------------------------------------------
# Pydantic models
# --------------------------------------------------------------------------------------

class APIMessage(BaseModel):
    message: str = Field(..., description="Human-readable message")

class UserPublic(BaseModel):
    id: str = Field(..., description="User unique identifier")
    email: EmailStr = Field(..., description="User email")
    name: Optional[str] = Field(None, description="Display name")

class UserCreate(BaseModel):
    email: EmailStr = Field(..., description="Email for registration and login")
    password: str = Field(..., min_length=6, description="Password with minimum 6 characters")
    name: Optional[str] = Field(None, description="Display name")

class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="Email for login")
    password: str = Field(..., description="Password for login")

class AuthResponse(BaseModel):
    access_token: str = Field(..., description="Bearer token to be used in Authorization header")
    token_type: str = Field("bearer", description="Token type")
    user: UserPublic = Field(..., description="Logged-in user profile")

class PhotoBase(BaseModel):
    title: Optional[str] = Field(None, description="Title of the photo")
    description: Optional[str] = Field(None, description="Description or notes")
    location: Optional[str] = Field(None, description="Human-readable location (city, country, etc.)")
    latitude: Optional[float] = Field(None, description="Latitude, if available")
    longitude: Optional[float] = Field(None, description="Longitude, if available")
    image_url: str = Field(..., description="URL to the image")

class PhotoCreate(PhotoBase):
    pass

class PhotoUpdate(BaseModel):
    title: Optional[str] = Field(None, description="Title of the photo")
    description: Optional[str] = Field(None, description="Description or notes")
    location: Optional[str] = Field(None, description="Human-readable location (city, country, etc.)")
    latitude: Optional[float] = Field(None, description="Latitude, if available")
    longitude: Optional[float] = Field(None, description="Longitude, if available")
    image_url: Optional[str] = Field(None, description="URL to the image")

class PhotoOut(PhotoBase):
    id: str = Field(..., description="Photo unique identifier")
    user_id: str = Field(..., description="Owner user id")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

class UnsplashImage(BaseModel):
    id: str = Field(..., description="Unsplash image ID")
    description: Optional[str] = Field(None, description="Photo description")
    alt_description: Optional[str] = Field(None, description="Photo alt description")
    url_small: str = Field(..., description="Small URL")
    url_full: str = Field(..., description="Full size URL")
    photographer: Optional[str] = Field(None, description="Photographer name")
    location: Optional[str] = Field(None, description="Location if available")

class UnsplashSearchResponse(BaseModel):
    total: int = Field(..., description="Total results")
    total_pages: int = Field(..., description="Total pages")
    results: List[UnsplashImage] = Field(..., description="Search results")

# --------------------------------------------------------------------------------------
# FastAPI application and metadata
# --------------------------------------------------------------------------------------

openapi_tags = [
    {"name": "Health", "description": "Service health and docs"},
    {"name": "Auth", "description": "User authentication endpoints"},
    {"name": "Photos", "description": "CRUD operations for user photos"},
    {"name": "Search", "description": "Location-based search for photos"},
    {"name": "Unsplash", "description": "External Unsplash API integration"},
]

app = FastAPI(
    title="Travel Photo Backend",
    description="Backend API for authentication, photo management, location search, and Unsplash integration.",
    version="1.0.0",
    openapi_tags=openapi_tags,
)

# CORS for frontend integration; in production, restrict to specific origin(s)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "*")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------------------
# Health and docs routes
# --------------------------------------------------------------------------------------

@app.get("/", summary="Health Check", tags=["Health"])
def health_check() -> Dict[str, str]:
    """
    PUBLIC_INTERFACE
    Health check endpoint to verify the service is running.

    Returns:
        JSON message indicating health status.
    """
    return {"message": "Healthy"}

# --------------------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------------------

@app.post(
    "/auth/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    tags=["Auth"],
    responses={
        201: {"description": "User registered"},
        400: {"description": "Email already registered"},
    },
)
def register(payload: UserCreate) -> AuthResponse:
    """
    PUBLIC_INTERFACE
    Register a new user with email, password, and optional name.

    Parameters:
        payload: UserCreate with email, password, and optional name.

    Returns:
        AuthResponse with access token and user profile.
    """
    if payload.email.lower() in USERS_BY_EMAIL:
        raise HTTPException(status_code=400, detail="Email is already registered")
    user_id = str(uuid4())
    USERS[user_id] = {
        "id": user_id,
        "email": payload.email.lower(),
        # WARNING: Plain text password only for demonstration in this task.
        # Replace with hashed password in production.
        "password": payload.password,
        "name": payload.name or payload.email.split("@")[0],
    }
    USERS_BY_EMAIL[payload.email.lower()] = user_id
    token = _generate_token(user_id)
    user_public = UserPublic(id=user_id, email=payload.email.lower(), name=USERS[user_id]["name"])
    return AuthResponse(access_token=token, token_type="bearer", user=user_public)

@app.post(
    "/auth/login",
    response_model=AuthResponse,
    summary="Login user",
    tags=["Auth"],
    responses={
        200: {"description": "Authenticated"},
        401: {"description": "Invalid credentials"},
    },
)
def login(payload: UserLogin) -> AuthResponse:
    """
    PUBLIC_INTERFACE
    Authenticate a user with email and password.

    Parameters:
        payload: UserLogin containing email and password.

    Returns:
        AuthResponse with access token and user profile.
    """
    user_id = USERS_BY_EMAIL.get(payload.email.lower())
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    user = USERS[user_id]
    if user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = _generate_token(user_id)
    user_public = UserPublic(id=user_id, email=user["email"], name=user["name"])
    return AuthResponse(access_token=token, token_type="bearer", user=user_public)

@app.get(
    "/auth/me",
    response_model=UserPublic,
    summary="Get current user",
    tags=["Auth"],
)
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)) -> UserPublic:
    """
    PUBLIC_INTERFACE
    Return the profile information of the authenticated user.

    Returns:
        UserPublic
    """
    return UserPublic(id=current_user["id"], email=current_user["email"], name=current_user.get("name"))

# --------------------------------------------------------------------------------------
# Photo routes
# --------------------------------------------------------------------------------------

@app.post(
    "/photos",
    response_model=PhotoOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create photo",
    description="Create a new photo owned by the authenticated user.",
    tags=["Photos"],
)
def create_photo(
    payload: PhotoCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> PhotoOut:
    """
    PUBLIC_INTERFACE
    Create a photo for the authenticated user.

    Parameters:
        payload: PhotoCreate with image_url and optional metadata.

    Returns:
        PhotoOut with created photo details.
    """
    photo_id = str(uuid4())
    now = _now_utc()
    record = {
        "id": photo_id,
        "user_id": current_user["id"],
        "title": payload.title,
        "description": payload.description,
        "location": payload.location,
        "latitude": payload.latitude,
        "longitude": payload.longitude,
        "image_url": payload.image_url,
        "created_at": now,
        "updated_at": now,
    }
    PHOTOS[photo_id] = record
    return PhotoOut(**record)

@app.get(
    "/photos",
    response_model=List[PhotoOut],
    summary="List my photos",
    description="List photos owned by the authenticated user. Optional location filter.",
    tags=["Photos", "Search"],
)
def list_my_photos(
    location: Optional[str] = Query(None, description="Optional location substring to filter"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[PhotoOut]:
    """
    PUBLIC_INTERFACE
    List photos for the authenticated user with an optional text-based location filter.

    Parameters:
        location: Optional string to match on the photo's location field.

    Returns:
        List[PhotoOut]
    """
    items: List[PhotoOut] = []
    for p in PHOTOS.values():
        if p["user_id"] != current_user["id"]:
            continue
        if location:
            if not p.get("location"):
                continue
            if location.lower() not in p["location"].lower():
                continue
        items.append(PhotoOut(**p))
    # Sort by created_at desc
    items.sort(key=lambda x: x.created_at, reverse=True)
    return items

@app.get(
    "/photos/{photo_id}",
    response_model=PhotoOut,
    summary="Get photo by id",
    tags=["Photos"],
)
def get_photo(
    photo_id: str = Path(..., description="Photo ID"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> PhotoOut:
    """
    PUBLIC_INTERFACE
    Get a single photo by id owned by the authenticated user.

    Returns:
        PhotoOut
    """
    record = PHOTOS.get(photo_id)
    if not record or record["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Photo not found")
    return PhotoOut(**record)

@app.put(
    "/photos/{photo_id}",
    response_model=PhotoOut,
    summary="Update photo",
    tags=["Photos"],
)
def update_photo(
    payload: PhotoUpdate,
    photo_id: str = Path(..., description="Photo ID"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> PhotoOut:
    """
    PUBLIC_INTERFACE
    Update fields on an existing photo.

    Returns:
        PhotoOut with updated fields.
    """
    record = PHOTOS.get(photo_id)
    if not record or record["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Photo not found")
    changed = False
    for field in ["title", "description", "location", "latitude", "longitude", "image_url"]:
        val = getattr(payload, field)
        if val is not None:
            record[field] = val
            changed = True
    if changed:
        record["updated_at"] = _now_utc()
    PHOTOS[photo_id] = record
    return PhotoOut(**record)

@app.delete(
    "/photos/{photo_id}",
    response_model=APIMessage,
    summary="Delete photo",
    tags=["Photos"],
)
def delete_photo(
    photo_id: str = Path(..., description="Photo ID"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> APIMessage:
    """
    PUBLIC_INTERFACE
    Delete an existing photo owned by the authenticated user.

    Returns:
        APIMessage indicating deletion.
    """
    record = PHOTOS.get(photo_id)
    if not record or record["user_id"] != current_user["id"]:
        raise HTTPException(status_code=404, detail="Photo not found")
    del PHOTOS[photo_id]
    return APIMessage(message="Photo deleted")

# --------------------------------------------------------------------------------------
# Location-based search across all my photos (more specific endpoint)
# --------------------------------------------------------------------------------------

@app.get(
    "/search/photos",
    response_model=List[PhotoOut],
    summary="Search my photos by location",
    description="Search within the authenticated user's photos by a location substring.",
    tags=["Search"],
)
def search_my_photos_by_location(
    q: str = Query(..., description="Location query substring"),
    current_user: Dict[str, Any] = Depends(get_current_user),
) -> List[PhotoOut]:
    """
    PUBLIC_INTERFACE
    Search photos by location for the authenticated user.

    Parameters:
        q: Search query string to be matched against the 'location' field.

    Returns:
        List[PhotoOut]
    """
    items: List[PhotoOut] = []
    needle = q.strip().lower()
    for p in PHOTOS.values():
        if p["user_id"] != current_user["id"]:
            continue
        loc = (p.get("location") or "").lower()
        if needle in loc:
            items.append(PhotoOut(**p))
    items.sort(key=lambda x: x.created_at, reverse=True)
    return items

# --------------------------------------------------------------------------------------
# Unsplash integration
# --------------------------------------------------------------------------------------

UNSPLASH_ACCESS_KEY = os.getenv("UNSPLASH_ACCESS_KEY", "").strip()
UNSPLASH_API_BASE = "https://api.unsplash.com"

def _require_unsplash_key():
    if not UNSPLASH_ACCESS_KEY:
        raise HTTPException(
            status_code=500,
            detail="UNSPLASH_ACCESS_KEY is not configured. Please set it via environment variable.",
        )

def _map_unsplash_result(item: Dict[str, Any]) -> UnsplashImage:
    urls = item.get("urls") or {}
    user = item.get("user") or {}
    # Location field in Unsplash search results is inconsistent; best-effort
    loc_obj = item.get("location") or {}
    loc_str = None
    if isinstance(loc_obj, dict):
        city = (loc_obj.get("city") or "") if loc_obj else ""
        country = (loc_obj.get("country") or "") if loc_obj else ""
        loc_parts = [x for x in [city, country] if x]
        loc_str = ", ".join(loc_parts) if loc_parts else None
    return UnsplashImage(
        id=item.get("id"),
        description=item.get("description"),
        alt_description=item.get("alt_description"),
        url_small=urls.get("small") or urls.get("regular") or urls.get("full") or "",
        url_full=urls.get("full") or urls.get("regular") or urls.get("small") or "",
        photographer=(user.get("name") if isinstance(user, dict) else None),
        location=loc_str,
    )

@app.get(
    "/unsplash/search",
    response_model=UnsplashSearchResponse,
    summary="Search Unsplash photos",
    description="Search images from Unsplash by query string.",
    tags=["Unsplash"],
    responses={
        200: {"description": "Search results from Unsplash"},
        500: {"description": "Unsplash key not configured or external error"},
    },
)
async def unsplash_search(
    query: str = Query(..., description="Search query string for Unsplash"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(12, ge=1, le=30, description="Results per page (max 30 by Unsplash)"),
) -> UnsplashSearchResponse:
    """
    PUBLIC_INTERFACE
    Search Unsplash for images by query.

    Parameters:
        query: search keywords
        page: page number
        per_page: results per page

    Returns:
        UnsplashSearchResponse with mapped results.
    """
    _require_unsplash_key()
    headers = {"Accept-Version": "v1", "Authorization": f"Client-ID {UNSPLASH_ACCESS_KEY}"}
    url = f"{UNSPLASH_API_BASE}/search/photos"
    params = {"query": query, "page": page, "per_page": per_page}
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"Unsplash error: {resp.text}")
            data = resp.json()
            results_raw = data.get("results") or []
            mapped = [_map_unsplash_result(x) for x in results_raw]
            return UnsplashSearchResponse(
                total=int(data.get("total") or 0),
                total_pages=int(data.get("total_pages") or 0),
                results=mapped,
            )
        except httpx.RequestError as e:
            raise HTTPException(status_code=500, detail=f"Error contacting Unsplash: {str(e)}") from e

# --------------------------------------------------------------------------------------
# WebSocket documentation helper (no sockets implemented here)
# --------------------------------------------------------------------------------------

@app.get(
    "/docs/websocket",
    summary="WebSocket usage note",
    description="This project does not use WebSockets. Clients should interact with REST endpoints.",
    tags=["Health"],
)
def websocket_docs_note() -> APIMessage:
    """
    PUBLIC_INTERFACE
    Informational endpoint documenting that no WebSocket endpoints are used.
    """
    return APIMessage(message="No WebSocket endpoints; use REST API instead.")
