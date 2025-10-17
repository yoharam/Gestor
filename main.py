from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List
import sqlite3
import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import jwt
from datetime import datetime, timedelta
import os
from contextlib import contextmanager
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración
app = FastAPI(
    title="Gestor de Contraseñas Seguro",
    description="API para gestión segura de contraseñas",
    version="2.0.0"
)

security = HTTPBearer()

# En producción, usar variables de entorno
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION = 24  # horas
SALT = os.getenv("SALT", "fixed_salt_for_demo")  # En producción usar salt único por usuario

# CORS para permitir acceso desde frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Modelos Pydantic con validación
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    master_password: str = Field(..., min_length=8)

class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    master_password: str

class PasswordCreate(BaseModel):
    site: str = Field(..., min_length=1, max_length=100)
    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1)
    notes: Optional[str] = Field(None, max_length=500)

class PasswordUpdate(BaseModel):
    site: Optional[str] = Field(None, min_length=1, max_length=100)
    username: Optional[str] = Field(None, min_length=1, max_length=100)
    password: Optional[str] = Field(None, min_length=1)
    notes: Optional[str] = Field(None, max_length=500)

class PasswordResponse(BaseModel):
    id: int
    site: str
    username: str
    password: str
    notes: Optional[str]
    created_at: str
    updated_at: str

# Context manager para base de datos
@contextmanager
def get_db_connection():
    conn = sqlite3.connect('passwords.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Inicialización de base de datos mejorada
def init_db():
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Tabla de usuarios
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            master_password_hash TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )''')
        
        # Tabla de contraseñas
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        
        # Índices para mejor rendimiento
        c.execute('''CREATE INDEX IF NOT EXISTS idx_user_id ON passwords(user_id)''')
        c.execute('''CREATE INDEX IF NOT EXISTS idx_username ON users(username)''')
        
        conn.commit()

init_db()

# Utilidades de encriptación mejoradas
def hash_password(password: str, salt: str = SALT) -> str:
    """Hash seguro de contraseña con salt"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Número de iteraciones
    ).hex()

def generate_encryption_key(master_password: str, salt: str = SALT) -> str:
    """Genera clave de encriptación usando PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key.decode()

def encrypt_password(password: str, key: str) -> str:
    """Encripta contraseña usando Fernet"""
    try:
        f = Fernet(key.encode())
        return f.encrypt(password.encode()).decode()
    except Exception as e:
        logger.error(f"Error encriptando contraseña: {e}")
        raise HTTPException(status_code=500, detail="Error encriptando contraseña")

def decrypt_password(encrypted_password: str, key: str) -> str:
    """Desencripta contraseña usando Fernet"""
    try:
        f = Fernet(key.encode())
        return f.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logger.error(f"Error desencriptando contraseña: {e}")
        raise HTTPException(status_code=500, detail="Error desencriptando contraseña")

def create_jwt_token(user_id: int, username: str) -> str:
    """Crea token JWT"""
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verifica y decodifica token JWT"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Token expirado")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logger.warning("Token inválido")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Endpoint para servir el frontend
@app.get("/")
async def serve_frontend():
    """Sirve el archivo index.html en la ruta raíz"""
    try:
        return FileResponse('index.html')
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Frontend no encontrado. Asegúrate de que index.html esté en el directorio raíz."
        )

# Endpoints de la API
@app.post("/api/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    """Registro de nuevo usuario"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        try:
            # Verificar si el usuario ya existe
            c.execute("SELECT id FROM users WHERE username = ?", (user.username,))
            if c.fetchone():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El usuario ya existe"
                )
            
            password_hash = hash_password(user.master_password)
            encryption_key = generate_encryption_key(user.master_password)
            
            c.execute(
                """INSERT INTO users (username, master_password_hash, encryption_key) 
                VALUES (?, ?, ?)""",
                (user.username, password_hash, encryption_key)
            )
            conn.commit()
            
            user_id = c.lastrowid
            token = create_jwt_token(user_id, user.username)
            
            logger.info(f"Usuario registrado: {user.username}")
            
            return {
                "message": "Usuario creado exitosamente",
                "token": token,
                "username": user.username
            }
            
        except sqlite3.Error as e:
            logger.error(f"Error de base de datos: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno del servidor"
            )

@app.post("/api/login")
async def login(user: UserLogin):
    """Inicio de sesión de usuario"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        password_hash = hash_password(user.master_password)
        
        c.execute(
            """SELECT id, username FROM users 
            WHERE username = ? AND master_password_hash = ?""",
            (user.username, password_hash)
        )
        
        result = c.fetchone()
        
        if not result:
            logger.warning(f"Intento de login fallido para usuario: {user.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas"
            )
        
        # Actualizar último login
        c.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (result["id"],)
        )
        conn.commit()
        
        user_id, username = result["id"], result["username"]
        token = create_jwt_token(user_id, username)
        
        logger.info(f"Login exitoso: {username}")
        
        return {
            "message": "Login exitoso",
            "token": token,
            "username": username
        }

@app.get("/api/passwords", response_model=dict)
async def get_passwords(payload: dict = Depends(verify_jwt_token)):
    """Obtener todas las contraseñas del usuario"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Obtener clave de encriptación del usuario
        c.execute("SELECT encryption_key FROM users WHERE id = ?", (payload["user_id"],))
        result = c.fetchone()
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
            
        encryption_key = result["encryption_key"]
        
        # Obtener contraseñas
        c.execute(
            """SELECT id, site, username, encrypted_password, notes, created_at, updated_at 
            FROM passwords WHERE user_id = ? ORDER BY site""",
            (payload["user_id"],)
        )
        
        passwords = []
        for row in c.fetchall():
            try:
                decrypted_password = decrypt_password(row["encrypted_password"], encryption_key)
                passwords.append({
                    "id": row["id"],
                    "site": row["site"],
                    "username": row["username"],
                    "password": decrypted_password,
                    "notes": row["notes"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"]
                })
            except Exception as e:
                logger.error(f"Error desencriptando contraseña ID {row['id']}: {e}")
                continue  # Saltar contraseñas que no se pueden desencriptar
        
        return {"passwords": passwords}

@app.post("/api/passwords", status_code=status.HTTP_201_CREATED)
async def create_password(password_data: PasswordCreate, payload: dict = Depends(verify_jwt_token)):
    """Crear nueva contraseña"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Obtener clave de encriptación
        c.execute("SELECT encryption_key FROM users WHERE id = ?", (payload["user_id"],))
        result = c.fetchone()
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
            
        encryption_key = result["encryption_key"]
        
        # Encriptar contraseña
        encrypted = encrypt_password(password_data.password, encryption_key)
        
        try:
            c.execute(
                """INSERT INTO passwords (user_id, site, username, encrypted_password, notes) 
                VALUES (?, ?, ?, ?, ?)""",
                (payload["user_id"], password_data.site, password_data.username, encrypted, password_data.notes)
            )
            
            conn.commit()
            password_id = c.lastrowid
            
            logger.info(f"Contraseña creada para usuario {payload['username']}")
            
            return {
                "message": "Contraseña guardada exitosamente",
                "id": password_id
            }
            
        except sqlite3.Error as e:
            logger.error(f"Error creando contraseña: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error guardando contraseña"
            )

@app.put("/api/passwords/{password_id}")
async def update_password(password_id: int, password_data: PasswordUpdate, payload: dict = Depends(verify_jwt_token)):
    """Actualizar contraseña existente"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Verificar que la contraseña pertenece al usuario
        c.execute("SELECT id FROM passwords WHERE id = ? AND user_id = ?", (password_id, payload["user_id"]))
        if not c.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contraseña no encontrada"
            )
        
        # Obtener clave de encriptación
        c.execute("SELECT encryption_key FROM users WHERE id = ?", (payload["user_id"],))
        result = c.fetchone()
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
            
        encryption_key = result["encryption_key"]
        
        # Construir query dinámica
        updates = []
        params = []
        
        if password_data.site is not None:
            updates.append("site = ?")
            params.append(password_data.site)
        if password_data.username is not None:
            updates.append("username = ?")
            params.append(password_data.username)
        if password_data.password is not None:
            updates.append("encrypted_password = ?")
            params.append(encrypt_password(password_data.password, encryption_key))
        if password_data.notes is not None:
            updates.append("notes = ?")
            params.append(password_data.notes)
        
        # Si no hay campos para actualizar
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se proporcionaron campos para actualizar"
            )
        
        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(password_id)
        
        query = f"UPDATE passwords SET {', '.join(updates)} WHERE id = ?"
        
        try:
            c.execute(query, params)
            conn.commit()
            
            logger.info(f"Contraseña {password_id} actualizada")
            
            return {"message": "Contraseña actualizada exitosamente"}
            
        except sqlite3.Error as e:
            logger.error(f"Error actualizando contraseña: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error actualizando contraseña"
            )

@app.delete("/api/passwords/{password_id}")
async def delete_password(password_id: int, payload: dict = Depends(verify_jwt_token)):
    """Eliminar contraseña"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        # Verificar existencia antes de eliminar
        c.execute("SELECT id FROM passwords WHERE id = ? AND user_id = ?", (password_id, payload["user_id"]))
        if not c.fetchone():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contraseña no encontrada"
            )
        
        c.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (password_id, payload["user_id"]))
        conn.commit()
        
        logger.info(f"Contraseña {password_id} eliminada")
        
        return {"message": "Contraseña eliminada exitosamente"}

@app.get("/api/user/profile")
async def get_user_profile(payload: dict = Depends(verify_jwt_token)):
    """Obtener perfil del usuario"""
    with get_db_connection() as conn:
        c = conn.cursor()
        
        c.execute(
            """SELECT username, created_at, last_login 
            FROM users WHERE id = ?""",
            (payload["user_id"],)
        )
        
        result = c.fetchone()
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Contar contraseñas del usuario
        c.execute("SELECT COUNT(*) as count FROM passwords WHERE user_id = ?", (payload["user_id"],))
        password_count = c.fetchone()["count"]
        
        return {
            "username": result["username"],
            "created_at": result["created_at"],
            "last_login": result["last_login"],
            "password_count": password_count
        }

@app.get("/api/health")
async def health_check():
    """Endpoint de salud de la API"""
    try:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT 1")
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )

if __name__ == "__main__":
    import uvicorn
    
    # Configuración para desarrollo
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=True  # Recarga automática en desarrollo
    )