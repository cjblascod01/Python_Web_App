import database
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey

class Usuarios(database.Base):
    __tablename__ = "Usuarios"

    dni = Column(String(9), primary_key=True)  # DNI del participante
    nombreCompletoUsuario = Column(String(200), nullable=False)
    mailUsuario = Column(String(200), unique=True, nullable=False)  # Clave única
    usuario = Column(String(200), unique=True, nullable=False) # Clave única
    contrasena = Column(String(200), nullable=False)  # Almacenada encriptada
    acceso = Column(String(50), nullable=False)  # Por ejemplo, 'usuarioComun', 'admin'

    def __init__(self, dni, nombreCompletoUsuario, mailUsuario, usuario, contrasena, acceso):
        self.dni = dni
        self.nombreCompletoUsuario = nombreCompletoUsuario
        self.mailUsuario = mailUsuario
        self.usuario = usuario
        self.contrasena = contrasena
        self.acceso = acceso

    def __repr__(self):
        return "Usuario {}: {} {} {} {} ({})".format(self.usuario, self.nombreCompletoUsuario, self.dni, self.mailUsuario, self.contrasena, self.acceso)

    def __str__(self):
        return "Usuario {}: {} {} {} {} ({})".format(self.usuario, self.nombreCompletoUsuario, self.dni, self.mailUsuario, self.contrasena, self.acceso)

class Torneos(database.Base):
    __tablename__ = "Torneos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    nombreTorneo = Column(String(200), unique=True, nullable=False)
    nombreJuego = Column(String(200), nullable=False)
    fechaInicio = Column(DateTime, nullable=False)
    fechaFin = Column(DateTime, nullable=False)
    inicioInscripcion = Column(DateTime, nullable=False)
    cierreInscripcion = Column(DateTime, nullable=False)
    limiteParticipantes = Column(Integer, nullable=False)  # Límite por categoría
    ganador = Column(String(200))

    @property
    def estado(self):
        now=datetime.now()
        return self.fechaInicio <= now <= self.fechaFin

    def __init__(self, nombreTorneo, nombreJuego, fechaInicio, fechaFin, inicioInscripcion, cierreInscripcion, limiteParticipantes, ganador):
        self.nombreTorneo = nombreTorneo
        self.nombreJuego = nombreJuego
        self.fechaInicio = fechaInicio
        self.fechaFin = fechaFin
        self.inicioInscripcion = inicioInscripcion
        self.cierreInscripcion = cierreInscripcion
        self.limiteParticipantes = limiteParticipantes
        self.ganador = ganador

    def __repr__(self):
        return "Torneo {}: {}. Fecha Torneo {} - {}. Fecha inscripciones: {} - {}. Limite de participantes {}. Ganador del torneo: {}".format(self.nombreTorneo, self.nombreJuego, self.fechaInicio, self.fechaFin, self.inicioInscripcion, self.cierreInscripcion, self.limiteParticipantes, self.ganador)

    def __str__(self):
        return "Torneo {}: {}. Fecha Torneo {} - {}. Fecha inscripciones: {} - {}. Limite de participantes {}. Ganador del torneo: {}".format(self.nombreTorneo, self.nombreJuego, self.fechaInicio, self.fechaFin, self.inicioInscripcion, self.cierreInscripcion, self.limiteParticipantes, self.ganador)

class Participantes(database.Base):
    __tablename__ = "Participantes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    usuario = Column(String(200), ForeignKey("Usuarios.usuario"), nullable=False)
    nombreTorneo = Column(String(200), ForeignKey("Torneos.nombreTorneo"), nullable=False)
    categoria = Column(String(50), nullable=False)  # Por ejemplo, 'principiante', 'avanzado'
    puntuacion = Column(Integer, default=0)

    def __init__(self, usuario, nombreTorneo, categoria, puntuacion):
        self.usuario = usuario
        self.nombreTorneo = nombreTorneo
        self.categoria = categoria
        self.puntuacion = puntuacion

    def __repr__(self):
        return "Participante {}: {}, torneo: {}, categoria: {}, puntuacion: {}".format(self.id, self.usuario, self.nombreTorneo, self.categoria, self.puntuacion)

    def __str__(self):
        return "Participante {}: {}, torneo: {}, categoria: {}, puntuacion: {}".format(self.id, self.usuario, self.nombreTorneo, self.categoria, self.puntuacion)