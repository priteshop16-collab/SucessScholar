"""
Success Scholar - Full-Stack Python Backend (FastAPI + SQLite)
==============================================================
How to run this full-stack application:
1. Ensure `index.html` is in the exact same folder as this `app.py` file.
2. Install required packages:
   pip install fastapi uvicorn pydantic
3. Start the server:
   uvicorn app:app --reload --port 8000
4. Open your browser to:
   http://127.0.0.1:8000
"""

import os
import io
import csv
import json
import hmac
import base64
import random
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from contextlib import contextmanager, asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from pydantic import BaseModel, Field

# ==============================================================================
# 1. CONFIGURATION & DATABASE SETUP
# ==============================================================================
DB_FILE = "success_scholar.db"
HTML_FILE = "index.html"
MAX_BATCH_CAPACITY = 50
TOKEN_SECRET_KEY = os.environ.get("SS_SECRET_KEY", "success-scholar-hmac-secret-2026-key").encode("utf-8")
TOKEN_TTL_HOURS = 12


def hash_password(password: str) -> str:
    """Hashes a plain-text password using salted PBKDF2-HMAC-SHA256 (120,000 iterations)."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a plain-text password against a salted PBKDF2 hash."""
    if "$" not in stored_hash:
        return hmac.compare_digest(hashlib.sha256(password.encode("utf-8")).hexdigest(), stored_hash)
    salt, expected_hex = stored_hash.split("$", 1)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return hmac.compare_digest(dk.hex(), expected_hex)


def create_access_token(user_id: str, role: str, full_name: str, email: str) -> str:
    """Creates a signed, expiring HMAC-SHA256 bearer token (zero external JWT dependencies)."""
    payload = {
        "sub": user_id,
        "role": role,
        "name": full_name,
        "email": email,
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=TOKEN_TTL_HOURS)).timestamp())
    }
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
    sig = hmac.new(TOKEN_SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def decode_access_token(token: str) -> dict:
    """Verifies token signature and expiration timestamp."""
    try:
        payload_b64, sig = token.split(".", 1)
        expected_sig = hmac.new(TOKEN_SECRET_KEY, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            raise ValueError("Invalid token signature")
        payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("utf-8")).decode("utf-8"))
        if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Token expired")
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired session token: {exc}"
        )


@contextmanager
def get_db_connection():
    """Context manager for safe SQLite database connections."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Enables accessing columns by name
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_database():
    """Creates tables and seeds initial data if the database is empty."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Create Courses Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS courses (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                level TEXT NOT NULL,
                duration TEXT NOT NULL,
                badge TEXT NOT NULL,
                rating REAL NOT NULL,
                description TEXT NOT NULL,
                syllabus_json TEXT NOT NULL
            )
        """)

        # Create Applications / Leads Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                college TEXT NOT NULL,
                degree TEXT NOT NULL,
                graduation_year TEXT NOT NULL,
                track TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'In Review',
                applied_at TEXT NOT NULL
            )
        """)

        # Create Users Table (Separate Student & Admin accounts with User ID + Password)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('student', 'admin')),
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        # Create Persistent Site Stats Table (Live Visitor Counter)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS site_stats (
                stat_key TEXT PRIMARY KEY,
                stat_value INTEGER NOT NULL
            )
        """)
        cursor.execute(
            "INSERT OR IGNORE INTO site_stats (stat_key, stat_value) VALUES ('total_visitors', 28941)"
        )

        # Seed Initial Courses if empty
        cursor.execute("SELECT COUNT(*) FROM courses")
        if cursor.fetchone()[0] == 0:
            initial_courses = [
                (
                    "cs-1", "Personality Development", "Soft Skills", "All Levels", "4 Weeks", "Popular", 4.9,
                    "Enhancing self-awareness, confidence, and positive attitude for an impactful professional presence across corporate environments.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Self-Awareness, Confidence Building & Growth Mindset"},
                        {"week": "Week 2", "topic": "Body Language, Grooming & Executive Presence"},
                        {"week": "Week 3", "topic": "Emotional Intelligence & Stress Resilience"},
                        {"week": "Week 4", "topic": "Personal Branding & Impactful Workplace Attitude"}
                    ])
                ),
                (
                    "cs-2", "POSH Training", "Corporate & Legal", "All Levels", "2 Weeks", "Compliance", 5.0,
                    "Educates employees and campus cohorts on legal compliance, prevention, prohibition, and redressal of sexual harassment at the workplace.",
                    json.dumps([
                        {"week": "Week 1", "topic": "POSH Act 2013 Legal Framework & Workplace Boundaries"},
                        {"week": "Week 2", "topic": "Internal Complaints Committee (ICC) Procedures & Case Studies"}
                    ])
                ),
                (
                    "cs-3", "Competitive Aptitude", "Aptitude & Sales", "Intermediate", "6 Weeks", "Placement Core", 4.9,
                    "Sharpening numerical, logical reasoning, data interpretation, and verbal skills for competitive exams and campus placements.",
                    json.dumps([
                        {"week": "Week 1-2", "topic": "Quantitative Aptitude, Speed Math & Number Systems"},
                        {"week": "Week 3-4", "topic": "Logical Reasoning, Analytical Puzzles & Data Sufficiency"},
                        {"week": "Week 5-6", "topic": "Verbal Ability, Reading Comprehension & Timed Mock Tests"}
                    ])
                ),
                (
                    "cs-4", "Sales Marketing & Branding", "Aptitude & Sales", "Intermediate", "5 Weeks", "Commercial", 4.8,
                    "Learn to identify target audiences, develop marketing strategies, drive consultative B2B/B2C sales, and build a lasting brand.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Market Segmentation, Buyer Personas & Value Proposition"},
                        {"week": "Week 2-3", "topic": "Consultative Selling, Objection Handling & Closing Deals"},
                        {"week": "Week 4-5", "topic": "Brand Positioning, Digital Campaigns & Growth Funnels"}
                    ])
                ),
                (
                    "cs-5", "Leadership Training", "Leadership", "Intermediate", "4 Weeks", "Executive", 4.9,
                    "Develop future leaders with strategic thinking, decision-making, team motivation, and constructive conflict resolution skills.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Strategic Thinking & Data-Backed Decision Making"},
                        {"week": "Week 2", "topic": "Team Motivation, Delegation & Accountability"},
                        {"week": "Week 3", "topic": "Conflict Resolution & High-Stakes Negotiation"},
                        {"week": "Week 4", "topic": "Leading Cross-Functional Teams Through Change"}
                    ])
                ),
                (
                    "cs-6", "Group Discussion & Personal Interview", "Interview Prep", "Advanced", "6 Weeks", "High Placement", 5.0,
                    "Techniques for communication, persuasive arguments, and structured responses in high-pressure Group Discussions and Personal Interviews.",
                    json.dumps([
                        {"week": "Week 1-2", "topic": "GD Entry/Exit Tactics, Persuasive Arguments & Moderation"},
                        {"week": "Week 3-4", "topic": "STAR Methodology & Behavioral HR Round Deconstruction"},
                        {"week": "Week 5-6", "topic": "Live Mock Corporate Panels & Personalized Feedback Scorecards"}
                    ])
                ),
                (
                    "cs-7", "Spoken English & Language Skill", "Spoken English", "Beginner to Intermediate", "8 Weeks", "Foundational", 4.8,
                    "Improve fluency, active business vocabulary, neutral pronunciation, and overall communication effectiveness in global workplaces.",
                    json.dumps([
                        {"week": "Week 1-2", "topic": "Phonetics, Neutral Pronunciation & Vocal Clarity"},
                        {"week": "Week 3-4", "topic": "Business Vocabulary, Idioms & Grammar Precision"},
                        {"week": "Week 5-6", "topic": "Extempore Speaking & Overcoming Stage Hesitation"},
                        {"week": "Week 7-8", "topic": "Live Debates, Town Hall Simulations & Q&A Fluency"}
                    ])
                ),
                (
                    "cs-8", "Corporate Training", "Corporate & Legal", "All Levels", "4 Weeks", "Enterprise", 4.9,
                    "Align employee skills with organizational goals, professional ethics, cross-functional teamwork, and modern business etiquette.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Organizational Goal Alignment & KPI Ownership"},
                        {"week": "Week 2", "topic": "Workplace Ethics, Integrity & Governance Standards"},
                        {"week": "Week 3", "topic": "Agile Teamwork & Cross-Department Collaboration"},
                        {"week": "Week 4", "topic": "Business Etiquette, Client Dining & Executive Comms"}
                    ])
                ),
                (
                    "cs-9", "C2C (Campus to Corporate)", "Campus Readiness", "Beginner", "6 Weeks", "Flagship", 4.95,
                    "Prepare students for the professional corporate world with ATS-ready resume building, LinkedIn optimization, and workplace decorum.",
                    json.dumps([
                        {"week": "Week 1-2", "topic": "ATS Resume Building, Cover Letters & Portfolio Structuring"},
                        {"week": "Week 3-4", "topic": "Workplace Decorum, Email Diplomacy & Corporate Hierarchy"},
                        {"week": "Week 5-6", "topic": "Capstone Corporate Simulation & Recruiter Readiness Audit"}
                    ])
                ),
                (
                    "cs-10", "NLP Fundamentals", "Creative & NLP", "All Levels", "4 Weeks", "Mindset", 4.85,
                    "Learn basic Neuro-Linguistic Programming (NLP) principles to improve interpersonal communication, rapport building, and achieve personal goals.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Foundations of Neuro-Linguistic Programming & Representational Systems"},
                        {"week": "Week 2", "topic": "Calibration, Mirroring & Deep Rapport Building"},
                        {"week": "Week 3", "topic": "Reframing Limiting Beliefs & Anchoring Peak Confidence"},
                        {"week": "Week 4", "topic": "Goal Setting Frameworks & Persuasive Language Patterns"}
                    ])
                ),
                (
                    "cs-11", "Film Making", "Creative & NLP", "Beginner to Intermediate", "6 Weeks", "Creative Studio", 4.9,
                    "Practical introduction to scriptwriting, cinematography, directing, visual storytelling, and digital post-production techniques.",
                    json.dumps([
                        {"week": "Week 1-2", "topic": "Screenplay Structure, Storyboarding & Visual Scriptwriting"},
                        {"week": "Week 3-4", "topic": "Camera Framing, Lighting Setups & On-Set Directing"},
                        {"week": "Week 5-6", "topic": "Non-Linear Video Editing, Sound Design & Color Grading"}
                    ])
                ),
                (
                    "cs-12", "Soft Skills Mastery", "Soft Skills", "All Levels", "4 Weeks", "Bestseller", 4.9,
                    "Master interpersonal finesse, emotional intelligence, active listening, and workplace etiquette demanded by Fortune 500 firms.",
                    json.dumps([
                        {"week": "Week 1", "topic": "Professional Etiquette & Executive Presence"},
                        {"week": "Week 2", "topic": "Conflict Resolution & Active Empathetic Listening"},
                        {"week": "Week 3", "topic": "High-Impact Cross-Functional Collaboration"},
                        {"week": "Week 4", "topic": "Corporate Presentation & Persuasive Storytelling"}
                    ])
                )
            ]
            cursor.executemany(
                "INSERT INTO courses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                initial_courses
            )

        # Seed Initial Applications if empty
        cursor.execute("SELECT COUNT(*) FROM applications")
        if cursor.fetchone()[0] == 0:
            initial_apps = [
                ("APP-1021", "Priyanshu Sharma", "priyanshu.s@heritage.edu.in", "+91 98310 44211", "Heritage Institute of Tech", "B.Tech / B.E.", "2026", "Interview Prep", "Admitted", "2 hours ago"),
                ("APP-1022", "Ananya Mukherjee", "ananya.m@jis.ac.in", "+91 94331 87652", "JIS College of Engineering", "B.Tech / B.E.", "2026", "Corporate Readiness", "In Review", "5 hours ago"),
                ("APP-1023", "Rohan Sen", "rohan.sen@iem.edu", "+91 91234 56789", "Institute of Engineering & Mgmt", "BBA / MBA", "2026", "Soft Skills", "Admitted", "1 day ago")
            ]
            cursor.executemany(
                "INSERT INTO applications VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                initial_apps
            )


# ==============================================================================
# 2. PYDANTIC DATA MODELS (REQUEST / RESPONSE VALIDATION)
# ==============================================================================
class LoginRequest(BaseModel):
    user_id: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=4, max_length=100)
    role: str = Field(..., pattern="^(student|admin)$")


class StudentRegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=3, max_length=30)
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=4, max_length=100)


class AdminRegisterRequest(BaseModel):
    user_id: str = Field(..., min_length=3, max_length=30)
    full_name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=120)
    password: str = Field(..., min_length=4, max_length=100)
    admin_secret_code: str = Field(..., min_length=4, max_length=50)


class ApplicationCreate(BaseModel):
    fullName: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=5, max_length=120)
    phone: str = Field(..., min_length=10, max_length=20)
    college: Optional[str] = "State University"
    degree: Optional[str] = "B.Tech / B.E."
    graduationYear: Optional[str] = "2026"
    interestTrack: str = "Campus-to-Corporate Readiness"


class StatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(Admitted|In Review|Rejected)$")


class CourseCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=120)
    category: str = Field(..., min_length=2, max_length=60)
    level: str = Field(default="All Levels", max_length=50)
    duration: str = Field(..., min_length=2, max_length=40)
    description: str = Field(..., min_length=10, max_length=600)
    week1Topic: str = Field(..., min_length=3, max_length=150)
    week2Topic: str = Field(..., min_length=3, max_length=150)


# ==============================================================================
# 3. FASTAPI APPLICATION & LIFECYCLE
# ==============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    yield


app = FastAPI(
    title="Success Scholar Full-Stack API",
    description="Backend API for Success Scholar EdTech Platform",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS so frontend and backend communicate smoothly across any port
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# 4. FRONTEND STATIC SERVING ROUTE
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    """Serves the single-file index.html frontend at the root URL and increments visitor count."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE site_stats SET stat_value = stat_value + 1 WHERE stat_key = 'total_visitors'")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    html_path = os.path.join(base_dir, HTML_FILE)
    if os.path.exists(html_path):
        return FileResponse(html_path)
    return HTMLResponse(
        content="<h1>index.html not found</h1><p>Place index.html in the same directory as app.py.</p>",
        status_code=404
    )


ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".svg"}


@app.get("/{image_filename}")
def serve_local_image(image_filename: str):
    """Serves local gallery and logo images placed in the same directory as app.py."""
    ext = os.path.splitext(image_filename)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(status_code=404, detail="File not found")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    safe_name = os.path.basename(image_filename)
    img_path = os.path.join(base_dir, safe_name)
    if os.path.isfile(img_path):
        return FileResponse(img_path)
    raise HTTPException(status_code=404, detail="Image not found")


@app.get("/api/stats")
def get_site_stats():
    """Returns persistent platform visitor stats from SQLite."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT stat_value FROM site_stats WHERE stat_key = 'total_visitors'")
        row = cursor.fetchone()
        return {"status": "success", "total_visitors": row["stat_value"] if row else 28941}


# ==============================================================================
# 5. REST API ENDPOINTS
# ==============================================================================
@app.post("/api/auth/login")
def login_user(payload: LoginRequest):
    """Validates User ID, Salted PBKDF2 Password, and Role ('student' or 'admin'), returning a signed token."""
    uid = payload.user_id.strip().upper()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, full_name, email, role, password_hash FROM users WHERE UPPER(user_id) = ? AND role = ?",
            (uid, payload.role)
        )
        user = cursor.fetchone()

        if not user or not verify_password(payload.password, user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid {payload.role.capitalize()} User ID or Password."
            )

        token = create_access_token(user["user_id"], user["role"], user["full_name"], user["email"])
        return {
            "status": "success",
            "token": token,
            "user": {
                "user_id": user["user_id"],
                "full_name": user["full_name"],
                "email": user["email"],
                "role": user["role"]
            }
        }


@app.post("/api/auth/register-student", status_code=status.HTTP_201_CREATED)
def register_student(payload: StudentRegisterRequest):
    """Creates a new Student account with salted password hash and issues a signed session token."""
    uid = payload.user_id.strip().upper()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE UPPER(user_id) = ?", (uid,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="This Student User ID is already taken.")

        now_str = datetime.now().strftime("%b %d, %Y")
        cursor.execute(
            "INSERT INTO users (user_id, full_name, email, role, password_hash, created_at) VALUES (?, ?, ?, 'student', ?, ?)",
            (uid, payload.full_name.strip(), payload.email.strip(), hash_password(payload.password), now_str)
        )

    token = create_access_token(uid, "student", payload.full_name.strip(), payload.email.strip())
    return {
        "status": "success",
        "token": token,
        "user": {
            "user_id": uid,
            "full_name": payload.full_name.strip(),
            "email": payload.email.strip(),
            "role": "student"
        }
    }


@app.post("/api/auth/register-admin", status_code=status.HTTP_201_CREATED)
def register_admin(payload: AdminRegisterRequest):
    """Registers a new Administrator account with salted password hash and signed session token."""
    if payload.admin_secret_code.strip() != "SS-ADMIN-2026":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Institution Admin Authorization Code."
        )

    uid = payload.user_id.strip().upper()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE UPPER(user_id) = ?", (uid,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="This Admin User ID is already registered.")

        now_str = datetime.now().strftime("%b %d, %Y")
        cursor.execute(
            "INSERT INTO users (user_id, full_name, email, role, password_hash, created_at) VALUES (?, ?, ?, 'admin', ?, ?)",
            (uid, payload.full_name.strip(), payload.email.strip(), hash_password(payload.password), now_str)
        )

    token = create_access_token(uid, "admin", payload.full_name.strip(), payload.email.strip())
    return {
        "status": "success",
        "token": token,
        "user": {
            "user_id": uid,
            "full_name": payload.full_name.strip(),
            "email": payload.email.strip(),
            "role": "admin"
        }
    }


@app.get("/api/courses")
def get_courses(category: Optional[str] = None, search: Optional[str] = None):
    """Fetches all courses with optional category and keyword filtering."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM courses WHERE 1=1"
        params = []

        if category and category.lower() != "all":
            query += " AND LOWER(category) = LOWER(?)"
            params.append(category)

        if search:
            query += " AND (LOWER(title) LIKE LOWER(?) OR LOWER(description) LIKE LOWER(?))"
            params.extend([f"%{search}%", f"%{search}%"])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            item = dict(row)
            item["syllabus"] = json.loads(item.pop("syllabus_json"))
            results.append(item)

        return {"status": "success", "count": len(results), "data": results}


@app.post("/api/courses", status_code=status.HTTP_201_CREATED)
def create_course(
    payload: CourseCreate,
    authorization: Optional[str] = Header(default=None)
):
    """Allows authenticated Administrators to publish a new training program."""
    verify_admin_token(authorization)
    course_id = f"cs-{random.randint(100, 999)}"
    syllabus = [
        {"week": "Week 1", "topic": payload.week1Topic.strip()},
        {"week": "Week 2", "topic": payload.week2Topic.strip()}
    ]
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO courses VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                course_id,
                payload.title.strip(),
                payload.category.strip(),
                payload.level.strip(),
                payload.duration.strip(),
                "New",
                4.9,
                payload.description.strip(),
                json.dumps(syllabus)
            )
        )
    return {
        "status": "success",
        "course": {
            "id": course_id,
            "title": payload.title.strip(),
            "category": payload.category.strip(),
            "level": payload.level.strip(),
            "duration": payload.duration.strip(),
            "badge": "New",
            "rating": 4.9,
            "description": payload.description.strip(),
            "syllabus": syllabus
        }
    }


@app.get("/api/applications")
def get_applications(search: Optional[str] = None):
    """Fetches all student applications for the Admin Management Portal."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if search:
            cursor.execute(
                """
                SELECT * FROM applications 
                WHERE LOWER(name) LIKE LOWER(?) 
                   OR LOWER(college) LIKE LOWER(?) 
                   OR LOWER(track) LIKE LOWER(?)
                ORDER BY rowid DESC
                """,
                (f"%{search}%", f"%{search}%", f"%{search}%")
            )
        else:
            cursor.execute("SELECT * FROM applications ORDER BY rowid DESC")

        rows = [dict(row) for row in cursor.fetchall()]

        total = len(rows)
        admitted = sum(1 for r in rows if r["status"] == "Admitted")
        in_review = sum(1 for r in rows if r["status"] == "In Review")
        seats_filled = min(admitted, MAX_BATCH_CAPACITY)

        return {
            "status": "success",
            "metrics": {
                "total": total,
                "admitted": admitted,
                "in_review": in_review,
                "max_capacity": MAX_BATCH_CAPACITY,
                "seats_filled": seats_filled,
                "is_full": seats_filled >= MAX_BATCH_CAPACITY
            },
            "data": rows
        }


@app.post("/api/applications", status_code=status.HTTP_201_CREATED)
def create_application(payload: ApplicationCreate):
    """Saves a new student enrollment/inquiry into the SQLite database (with duplicate guard)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM applications WHERE status = 'Admitted'")
        admitted_count = cursor.fetchone()[0]
        if admitted_count >= MAX_BATCH_CAPACITY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="All 50 seats for the Internship 2026 Immersion cohort are currently full."
            )

        # Prevent duplicate applications from the same email for the exact same track
        cursor.execute(
            "SELECT id FROM applications WHERE LOWER(email) = LOWER(?) AND LOWER(track) = LOWER(?)",
            (payload.email.strip(), payload.interestTrack.strip())
        )
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="You have already submitted an application for this specialization track."
            )

        app_id = f"APP-{random.randint(1000, 9999)}"
        applied_at = "Just now"

        cursor.execute(
            """
            INSERT INTO applications (id, name, email, phone, college, degree, graduation_year, track, status, applied_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'In Review', ?)
            """,
            (
                app_id,
                payload.fullName.strip(),
                payload.email.strip(),
                payload.phone.strip(),
                (payload.college or "State University").strip(),
                (payload.degree or "B.Tech / B.E.").strip(),
                (payload.graduationYear or "2026").strip(),
                payload.interestTrack.strip(),
                applied_at
            )
        )

    return {
        "status": "success",
        "message": "Application saved to SQLite database",
        "application": {
            "id": app_id,
            "name": payload.fullName.strip(),
            "email": payload.email.strip(),
            "phone": payload.phone.strip(),
            "college": (payload.college or "State University").strip(),
            "degree": (payload.degree or "B.Tech / B.E.").strip(),
            "graduation_year": (payload.graduationYear or "2026").strip(),
            "track": payload.interestTrack.strip(),
            "status": "In Review",
            "appliedAt": applied_at
        }
    }


def verify_admin_token(authorization: Optional[str]):
    """Verifies signed Bearer token and confirms active Admin role in SQLite."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing or invalid Administrator Bearer token."
        )
    token = authorization.split(" ", 1)[1].strip()
    claims = decode_access_token(token)
    if claims.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required for this action."
        )
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id FROM users WHERE UPPER(user_id) = ? AND role = 'admin'",
            (claims.get("sub", "").upper(),)
        )
        if not cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Administrator account not found."
            )
    return claims


@app.get("/api/applications/export")
def export_applications_csv(authorization: Optional[str] = Header(default=None)):
    """Exports all student applications as a downloadable CSV file (Admin Only)."""
    verify_admin_token(authorization)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, email, phone, college, degree, graduation_year, track, status, applied_at FROM applications ORDER BY rowid DESC")
        rows = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Application ID", "Full Name", "Email", "Phone", "College", "Degree", "Graduation Year", "Track", "Status", "Applied At"])
    for r in rows:
        writer.writerow([r["id"], r["name"], r["email"], r["phone"], r["college"], r["degree"], r["graduation_year"], r["track"], r["status"], r["applied_at"]])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=success_scholar_applications.csv"}
    )


@app.patch("/api/applications/{app_id}/status")
def update_application_status(
    app_id: str,
    payload: StatusUpdate,
    authorization: Optional[str] = Header(default=None)
):
    """Toggles or updates an applicant's admission status in the database (Admin Only)."""
    verify_admin_token(authorization)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, status FROM applications WHERE id = ?", (app_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Application ID not found")

        if payload.status == "Admitted" and row["status"] != "Admitted":
            cursor.execute("SELECT COUNT(*) FROM applications WHERE status = 'Admitted'")
            admitted_count = cursor.fetchone()[0]
            if admitted_count >= MAX_BATCH_CAPACITY:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Maximum cohort capacity ({MAX_BATCH_CAPACITY} seats) is already full."
                )

        cursor.execute(
            "UPDATE applications SET status = ? WHERE id = ?",
            (payload.status, app_id)
        )

    return {
        "status": "success",
        "id": app_id,
        "new_status": payload.status
    }


@app.delete("/api/applications/{app_id}")
def delete_application(
    app_id: str,
    authorization: Optional[str] = Header(default=None)
):
    """Deletes a duplicate or invalid student application from the database (Admin Only)."""
    verify_admin_token(authorization)

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM applications WHERE id = ?", (app_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Application ID not found")

        cursor.execute("DELETE FROM applications WHERE id = ?", (app_id,))

    return {"status": "success", "deleted_id": app_id}


if __name__ == "__main__":
    import uvicorn
    init_database()
    uvicorn.run(app, host="127.0.0.1", port=8000)