"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3
import os
import jwt

JWT_SECRET = os.getenv("JWT_SECRET")

from flask import Flask, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, jsonify

import os
from dotenv import load_dotenv

import jwt
from datetime import datetime, timedelta

load_dotenv()
JWT_SECRET = os.getenv("JWT_SECRET")

from functools import wraps

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        user_id = claims.get("sub")
        role = claims.get("role", "user")

        if user_id is None:
            return jsonify({"error": "Invalid token: missing subject"}), 401

        # pass user_id and role into the route
        return f(user_id, role, *args, **kwargs)

    return decorated

DATABASE = "recipes.db"

app = Flask(__name__)

def hash_password(plain_password: str) -> str:
    """Return a secure hash of the given plaintext password."""
    return generate_password_hash(plain_password, method="pbkdf2:sha256")


def verify_password(stored_hash: str, candidate_password: str) -> bool:
    """Return True if the candidate_password matches the stored hash."""
    return check_password_hash(stored_hash, candidate_password)

# then keep the rest: get_db, close_db, recipe routes, register, etc.

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))

@app.post("/recipes")
@app.route("/recipes", methods=["POST"])
@token_required
def create_recipe(user_id, role):
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201

@app.patch("/recipes/<int:recipe_id>")
@token_required
def update_recipe(user_id, role, recipe_id):
    db = get_db()

    # 1️⃣ Load the recipe first
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2️⃣ Enforce ownership OR admin
    is_owner = str(row["owner_id"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403

    # 3️⃣ Existing update logic (unchanged)
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400

    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    values.append(recipe_id)
    try:
        db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))

@app.delete("/recipes/<int:recipe_id>")
@token_required
def delete_recipe(user_id, role, recipe_id):
    
    db = get_db()

    # 1️⃣ Load the recipe first
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

   # 2️⃣ Enforce ownership OR admin
    is_owner = str(row["owner_id"]) == str(user_id)
    is_admin = role == "admin"

    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: you do not own this recipe"}), 403
    
    # 3️⃣ Owner is allowed: delete
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    # rowcount should be 1 here, but we can keep the check
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404

    return "", 204

@app.post("/login")
def login():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "a JSON body is required"}), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    db = get_db()
    user = db.execute(
        "SELECT id, email, password_hash, role FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    # Generic authentication failure: same response for "no such email" and "wrong password"
    if user is None or not verify_password(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    # Success: issue a signed JWT carrying the authenticated identity
    payload = {
        "sub": str(user["id"]),  # subject = user id as a string
        "role": user["role"],
        "exp": datetime.utcnow() + timedelta(hours=1),  # token expires in 1 hour
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({
        "id": user["id"],
        "email": user["email"],
        "token": token,
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=8000)