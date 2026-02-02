import os
import uuid
import enum
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import (
    Column, DateTime, ForeignKey, Integer, String,
    Table, Text, create_engine, Enum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, sessionmaker
from passlib.context import CryptContext
from jose import JWTError, jwt
from faker import Faker

# =======================
# CONFIG
# =======================

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database.db")

# =======================
# DATABASE SETUP
# =======================

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =======================
# ENUMS (CORRIGIDOS)
# =======================

class TipoTarefa(str, enum.Enum):
    ATIVIDADE = "ATIVIDADE"
    PROJETO = "PROJETO"

class StatusTarefa(str, enum.Enum):
    PENDENTE = "PENDENTE"
    EM_ANDAMENTO = "EM_ANDAMENTO"
    CONCLUIDA = "CONCLUIDA"

# =======================
# TABELA N:N PROFESSOR <-> DISCIPLINA (UUID)
# =======================

professor_disciplina = Table(
    'professor_disciplina',
    Base.metadata,
    Column('professor_id', UUID(as_uuid=True), ForeignKey('professor.id'), primary_key=True),
    Column('disciplina_id', UUID(as_uuid=True), ForeignKey('disciplina.id'), primary_key=True)
)

# =======================
# MODELS (TABELAS)
# =======================

class Turma(Base):
    __tablename__ = 'turma'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String, nullable=False)
    criada_em = Column(DateTime, default=datetime.utcnow)

    alunos = relationship('Aluno', back_populates='turma')


class Aluno(Base):
    __tablename__ = 'aluno'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)

    turma_id = Column(UUID(as_uuid=True), ForeignKey('turma.id'))

    criado_em = Column(DateTime, default=datetime.utcnow)
    atualizado_em = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    turma = relationship('Turma', back_populates='alunos')
    tarefas = relationship('Tarefa', back_populates='aluno')


class Disciplina(Base):
    __tablename__ = 'disciplina'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String, nullable=False)
    codigo = Column(String, nullable=True)

    professores = relationship(
        'Professor',
        secondary=professor_disciplina,
        back_populates='disciplinas'
    )

    tarefas = relationship('Tarefa', back_populates='disciplina')


class Professor(Base):
    __tablename__ = 'professor'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=True)

    disciplinas = relationship(
        'Disciplina',
        secondary=professor_disciplina,
        back_populates='professores'
    )

    tarefas = relationship('Tarefa', back_populates='professor')


class Tarefa(Base):
    __tablename__ = 'tarefa'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    aluno_id = Column(UUID(as_uuid=True), ForeignKey('aluno.id'), nullable=False)
    disciplina_id = Column(UUID(as_uuid=True), ForeignKey('disciplina.id'), nullable=False)
    professor_id = Column(UUID(as_uuid=True), ForeignKey('professor.id'), nullable=False)

    tipo = Column(Enum(TipoTarefa), nullable=False)
    titulo = Column(String, nullable=False)
    descricao = Column(Text, nullable=True)
    pontos = Column(Integer, default=0)
    data_entrega = Column(DateTime, nullable=True)
    status = Column(Enum(StatusTarefa), default=StatusTarefa.PENDENTE)

    iniciada_em = Column(DateTime, nullable=True)
    concluida_em = Column(DateTime, nullable=True)

    criada_em = Column(DateTime, default=datetime.utcnow)
    atualizada_em = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    aluno = relationship('Aluno', back_populates='tarefas')
    disciplina = relationship('Disciplina', back_populates='tarefas')
    professor = relationship('Professor', back_populates='tarefas')

# =======================
# SCHEMAS (Pydantic)
# =======================

class Token(BaseModel):
    access_token: str
    token_type: str

class AlunoOut(BaseModel):
    id: uuid.UUID
    nome: str
    email: Optional[str]
    turma_id: Optional[uuid.UUID]

    class Config:
        orm_mode = True

class ProfessorOut(BaseModel):
    id: uuid.UUID
    nome: str
    email: Optional[str]

    class Config:
        orm_mode = True

class DisciplinaOut(BaseModel):
    id: uuid.UUID
    nome: str
    codigo: Optional[str]

    class Config:
        orm_mode = True

class TarefaOut(BaseModel):
    id: uuid.UUID
    titulo: str
    descricao: Optional[str]
    pontos: int
    status: StatusTarefa
    tipo: TipoTarefa

    class Config:
        orm_mode = True

# =======================
# AUTH (JWT)
# =======================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(db: Session, email: str):
    return db.query(Aluno).filter(Aluno.email == email).first()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_email(db, username)
    if not user:
        return None
    if not verify_password(password, user.senha_hash):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    db = SessionLocal()
    user = get_user_by_email(db, username)
    db.close()

    if user is None:
        raise credentials_exception
    return user

# =======================
# APP
# =======================

app = FastAPI(
    title="Charlas Minimal API",
    description="API com seed, JWT, SQLAlchemy e Pydantic"
)

@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        if db.query(Aluno).first():
            return

        fake = Faker()

        # Turmas
        turmas = []
        for i in range(3):
            t = Turma(nome=f"Turma {i+1}")
            db.add(t)
            turmas.append(t)
        db.commit()

        # Disciplinas
        disciplinas = []
        for i in range(4):
            d = Disciplina(nome=fake.word().title(), codigo=f"D{i+1:03}")
            db.add(d)
            disciplinas.append(d)
        db.commit()

        # Professores
        professors = []
        for i in range(3):
            p = Professor(nome=fake.name(), email=f"prof{i+1}@example.com")
            db.add(p)
            professors.append(p)
        db.commit()

        # Relacionar professor-disciplina
        for i, d in enumerate(disciplinas):
            p = professors[i % len(professors)]
            p.disciplinas.append(d)
        db.commit()

        # Alunos
        for i in range(10):
            turma = turmas[i % len(turmas)]
            email = f"aluno{i+1}@example.com"
            aluno = Aluno(
                nome=fake.name(),
                email=email,
                senha_hash=get_password_hash('password'),
                turma=turma
            )
            db.add(aluno)
        db.commit()

        # Tarefas (AGORA COM ALUNO_ID)
        alunos = db.query(Aluno).all()
        for i in range(8):
            d = disciplinas[i % len(disciplinas)]
            p = professors[i % len(professors)]
            a = alunos[i % len(alunos)]

            ttask = Tarefa(
                titulo=fake.sentence(nb_words=4),
                descricao=fake.text(max_nb_chars=100),
                disciplina_id=d.id,
                professor_id=p.id,
                aluno_id=a.id,
                pontos=10,
                tipo=TipoTarefa.ATIVIDADE,
                status=StatusTarefa.PENDENTE
            )
            db.add(ttask)
        db.commit()

        print('Seed aplicado. Usuários criados com senha: "password"')

    finally:
        db.close()

# =======================
# ROTAS
# =======================

@app.post('/token', response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    db.close()

    if not user:
        raise HTTPException(status_code=400, detail='Incorrect username or password')

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/health')
def health():
    return {"status": "ok"}

@app.get('/alunos', response_model=List[AlunoOut])
def list_alunos(current_user: Aluno = Depends(get_current_user)):
    db = SessionLocal()
    alunos = db.query(Aluno).all()
    db.close()
    return alunos

@app.get('/professores', response_model=List[ProfessorOut])
def list_professores(current_user: Aluno = Depends(get_current_user)):
    db = SessionLocal()
    profs = db.query(Professor).all()
    db.close()
    return profs

@app.get('/disciplinas', response_model=List[DisciplinaOut])
def list_disciplinas(current_user: Aluno = Depends(get_current_user)):
    db = SessionLocal()
    ds = db.query(Disciplina).all()
    db.close()
    return ds

@app.get('/tarefas', response_model=List[TarefaOut])
def list_tarefas(current_user: Aluno = Depends(get_current_user)):
    db = SessionLocal()
    ts = db.query(Tarefa).filter(Tarefa.aluno_id == current_user.id).all()
    db.close()
    return ts

@app.get('/')
def root():
    return {"message": "Charlas minimal API. See /docs for OpenAPI docs"}

