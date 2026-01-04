import database
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func, and_, update
from models import Usuarios, Torneos, Participantes
from datetime import datetime
import os

app = Flask(__name__)
# Configurar una clave secreta para las sesiones
app.secret_key = 'mr7pMYH93N2f'
# Registrar 'enumerate' como función global en Jinja2
app.jinja_env.globals.update(enumerate=enumerate)

#·····································#
# OPERACIONES PARA GESTIONAR LOGS #
#·····································#
def escribir_log(texto,nivel_traza):
    now = datetime.now()
    filename = "./logs/"+ now.strftime("%Y-%m-%d") + ".log"
    traza = now.strftime("[%Y-%m-%d %H:%M:%S] ") + f"[{nivel_traza}] " + texto + "\n"
    log = open(filename, "a", encoding="utf8")
    log.write(traza)
    log.close()

#·····································#
# OPERACIONES PARA GESTIONAR SESIONES #
#·····································#

# Funcion para crear el usuario administrador automaticamente
def generar_admin():
    if not database.session.query(Usuarios).filter_by(acceso='admin').first():
        usuario = Usuarios(
            dni='99999999Z',
            nombreCompletoUsuario='Usuario Admin',
            mailUsuario='root@toor.com',
            usuario='admin',
            contrasena=generate_password_hash('admin'),  # Hash seguro
            acceso='admin'
        )
        database.session.add(usuario)
        try:
            escribir_log(f"Se ha creado el usuario administrador {usuario.usuario}","INFO")
            database.session.commit()
        except Exception as e:
            escribir_log(f"{str(e)}","ERROR")
            database.session.rollback()

# Manejo de errores
@app.errorhandler(403)
def acceso_denegado(e):
    return "Acceso denegado. No tienes permiso para acceder a esta página.", 403

# Decorador para restringir rutas segun nivel de acceso en usuarios
def requiere_admin(funcion):
    @wraps(funcion)
    def funcion_envuelta(*args, **kwargs):
        # Verificar si el usuario se encuentra en la sesion y si tiene nivel de acceso suficiente
        if session.get('acceso') != 'admin':
            return abort(403)
        return funcion(*args, **kwargs)
    return funcion_envuelta

def requiere_usuario(funcion):
    @wraps(funcion)
    def funcion_envuelta(*args, **kwargs):
        # Verificar si el usuario se encuentra en la sesion
        if 'usuario' not in session:
            return abort(403)  # Prohibido, no tiene permiso
        return funcion(*args, **kwargs)

    return funcion_envuelta

# Función para comprobar existencia de usuario
def comprobar_usuario(usuario):
    # Comprobar que todos los campos requeridos están presentes y no vacíos
    campos_requeridos = ['dni', 'nombreCompletoUsuario', 'mailUsuario', 'usuario', 'contrasena', 'acceso']
    for campo in campos_requeridos:
        if not getattr(usuario, campo, None):  # Usamos getattr para acceder dinámicamente a los atributos
            raise Exception(f'El campo: "{campo}" se encuentra vacio.')

    # Realizar una consulta para verificar si existe algún conflicto, de modo que filtramos mediante varios OR para que almacene en variable el primer resultado que coincida con alguno de los filtros
    query = database.session.query(Usuarios).filter(
        (Usuarios.dni == usuario.dni) |
        (Usuarios.mailUsuario == usuario.mailUsuario) |
        (Usuarios.usuario == usuario.usuario)
    ).first()

    if query:
        # Identificar el campo que genera el conflicto
        if query.dni == usuario.dni:
            raise Exception(f'El DNI "{usuario.dni}" ya ha sido registrado.')
        if query.mailUsuario == usuario.mailUsuario:
            raise Exception(f'El email "{usuario.mailUsuario}" ya ha sido registrado.')
        if query.usuario == usuario.usuario:
            raise Exception(f'El usuario "{usuario.usuario}" ya ha sido registrado.')

@app.route("/")
def home():
    return render_template("index.html")

# Página de registro
@app.route('/registro')
def home_registro():
    return render_template("registro.html")

@app.route("/registro/crear-usuario", methods=['POST'])
def crear_usuario():

    usuario = Usuarios(
        dni=request.form['dni'],
        nombreCompletoUsuario=request.form['nombreCompletoUsuario'],
        mailUsuario=request.form['mailUsuario'],
        usuario=request.form['usuario'],
        contrasena=generate_password_hash(request.form['contrasena']),
        acceso='user'
    )

    try:
        comprobar_usuario(usuario)
        database.session.add(usuario)
        database.session.commit()
        escribir_log(f"Se ha creado el usuario {usuario.usuario} - {usuario.acceso}","INFO")
        flash("Usuario creado correctamente", "success")
        return redirect(url_for('home'))
    except Exception as e:
        database.session.rollback()
        escribir_log(f"{str(e)}","ERROR")
        flash("No ha sido posible crear el usuario", "error")
        return redirect(url_for('home_registro'))



@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        query = database.session.query(Usuarios).filter(
            (Usuarios.usuario == request.form['identificador']) |
            (Usuarios.mailUsuario == request.form['identificador'])
        ).first()
        if query:
            if check_password_hash(query.contrasena, request.form['contrasena']):
                session['acceso'] = query.acceso
                session['usuario'] = query.usuario
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - ha iniciado sesión correctamente", "INFO")
                return redirect(url_for('home_sesion'))
            else:
                escribir_log(f"Error de acceso usuario {request.form['identificador']}. Credenciales invalidas", "ERROR")
                flash("Las credenciales no son correctas", "error")
                return redirect(url_for('home'))
        else:
            escribir_log(f"Error de acceso usuario {request.form['identificador']}. Usuario no existe", "ERROR")
            flash(f"El usuario {request.form['identificador']} no existe", "error")
            return redirect(url_for('home'))

@app.route('/logout')
def logout():
    escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha desconectado", "INFO")
    session.clear()
    flash("Te has desconectado correctamente", "success")
    return redirect(url_for('home'))

@app.route('/session')
@requiere_usuario
def home_sesion():
    usuario_loged = database.session.query(Usuarios).filter_by(usuario=session['usuario']).first()
    if session['acceso'] == 'admin':
        return render_template("admin.html",usuario_loged=usuario_loged)
    else:
        return render_template("usuario.html",usuario_loged=usuario_loged)

#·································#
# OPERACIONES PARA USUARIOS ADMIN #
#·································#
"""
OPERACIONES CON LOGS
"""
@app.route('/logs')
@requiere_admin
def mostrar_logs():
    lista_de_logs = os.listdir(r'./logs')
    logs_contenido = {}

    for log in lista_de_logs:
        try:
            with open(f'./logs/{log}', 'r') as fichero:
                logs_contenido[log] = fichero.readlines()
        except Exception as e:
            logs_contenido[log] = f"Error al leer el archivo: {str(e)}"

    return render_template('listaLogs.html', lista_de_logs=lista_de_logs, logs_contenido=logs_contenido)

"""
OPERACIONES CON USUARIOS
"""
@app.route('/listaUsuarios')
@requiere_admin
def listar_usuarios():
    lista_de_usuarios = database.session.query(Usuarios).order_by(Usuarios.usuario, Usuarios.acceso).all()
    return render_template('listaUsuarios.html',lista_de_usuarios=lista_de_usuarios)

@requiere_admin
@app.route("/listaUsuarios/crear-usuario", methods=['POST'])
def admin_crear_usuario():

    usuario = Usuarios(
        dni=request.form['dni'],
        nombreCompletoUsuario=request.form['nombreCompletoUsuario'],
        mailUsuario=request.form['mailUsuario'],
        usuario=request.form['usuario'],
        contrasena=generate_password_hash(request.form['contrasena']),
        acceso=request.form['acceso']
    )

    try:
        comprobar_usuario(usuario)
        database.session.add(usuario)
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Usuario creado: {usuario.usuario}.", "INFO")
        flash("Se ha creado el usuario correctamente", "success")
    except Exception as e:
        database.session.rollback()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
        flash("No ha sido posible crear el usuario", "error")

    return redirect(url_for('listar_usuarios'))

@app.route('/listaUsuarios/borrar-usuario/<usuario>')
@requiere_admin
def borrar_usuario(usuario):
    try:
        database.session.query(Usuarios).filter_by(usuario=usuario).delete()
        database.session.query(Participantes).filter_by(usuario=usuario).delete()
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha borrado el usuario {usuario}", "INFO")
        flash("Usuario borrado correctamente", "success")
    except Exception as e:
        database.session.rollback()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
        flash("Hubo problemas para borrar el usuario", "error")
    return redirect(url_for('listar_usuarios'))


@app.route('/editar-usuario/<usuario>', methods=['POST', 'GET'])
@requiere_usuario
def editar_usuario(usuario):
    busqueda_usuario = database.session.query(Usuarios).filter_by(usuario=usuario).first()
    usuario_antiguo = busqueda_usuario.usuario
    if not busqueda_usuario:
        if session['acceso'] == 'admin':
            return redirect(url_for('listar_usuarios'))
        else:
            return redirect(url_for('home_sesion'))

    # Verificar si el usuario tiene permiso para editar
    if session['acceso'] != 'admin' and session['usuario'] != usuario:
        return redirect(url_for('home_sesion'))

    if request.method == 'POST':
        nuevo_dni = request.form.get('dni')
        nuevo_nombreCompletoUsuario = request.form.get('nombreCompletoUsuario')
        nuevo_mailUsuario = request.form.get('mailUsuario')
        nuevo_usuario = request.form.get('usuario')
        nuevo_contrasena = request.form.get('contrasena')

        if session['acceso'] == 'admin':
            nuevo_acceso = request.form.get('acceso')
            if nuevo_acceso:
                busqueda_usuario.acceso = nuevo_acceso

        errores = []

        # Validación de DNI único
        if nuevo_dni:
            busqueda_nuevo_usuario = database.session.query(Usuarios).filter_by(dni=nuevo_dni).first()
            if busqueda_nuevo_usuario:
                errores.append(f'Error, el dni {nuevo_dni} ya existe en la base de datos')

        # Validación de email único
        if nuevo_mailUsuario:
            busqueda_nuevo_usuario = database.session.query(Usuarios).filter_by(mailUsuario=nuevo_mailUsuario).first()
            if busqueda_nuevo_usuario:
                errores.append(f'Error, el email {nuevo_mailUsuario} ya existe en la base de datos')

        # Validación de usuario único
        if nuevo_usuario:
            busqueda_nuevo_usuario = database.session.query(Usuarios).filter_by(usuario=nuevo_usuario).first()
            if busqueda_nuevo_usuario:
                errores.append(f'Error, el nombre de usuario {nuevo_usuario} ya existe en la base de datos')

        if errores:
            for error in errores:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {error}", "ERROR")
            return render_template('editarUsuario.html', usuario=busqueda_usuario)
        else:
            # Actualizar campos
            if nuevo_dni:
                busqueda_usuario.dni = nuevo_dni
            if nuevo_nombreCompletoUsuario:
                busqueda_usuario.nombreCompletoUsuario = nuevo_nombreCompletoUsuario
            if nuevo_mailUsuario:
                busqueda_usuario.mailUsuario = nuevo_mailUsuario
            if nuevo_usuario:
                query = update(Participantes).where(Participantes.usuario == usuario_antiguo).values(usuario=nuevo_usuario)
                database.session.execute(query)
                busqueda_usuario.usuario = nuevo_usuario

                # Actualizar la sesión si el usuario está cambiando su propio nombre
                if session['usuario'] == usuario_antiguo:
                    session['usuario'] = nuevo_usuario

            if nuevo_contrasena:
                busqueda_usuario.contrasena = generate_password_hash(nuevo_contrasena)

            try:
                if nuevo_usuario:
                    escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Ha modificado los datos del usuario {usuario} -> {nuevo_usuario}","INFO")
                else:
                    escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Ha modificado los datos del usuario {usuario}", "INFO")
                database.session.commit()
                flash("Usuario editado correctamente", "success")
            except Exception as e:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
                flash("Error al modificar el usuario", "error")
                database.session.rollback()

            # Redirigir según el rol del usuario
            if session['acceso'] == 'admin':
                return redirect(url_for('listar_usuarios'))
            else:
                return redirect(url_for('home_sesion'))

    return render_template('editarUsuario.html', usuario=busqueda_usuario, session=session)

"""
OPERACIONES CON TORNEOS
"""
# Lista de torneos
@app.route('/listaTorneos')
@requiere_admin
def listar_torneos():
    # Obtener todos los torneos
    lista_de_torneos = database.session.query(Torneos).order_by(Torneos.nombreTorneo, Torneos.nombreJuego).all()

    # Filtrar los torneos por estado
    now = datetime.now()
    torneos_activos = [torneo for torneo in lista_de_torneos if torneo.fechaInicio <= now <= torneo.fechaFin]
    torneos_inactivos = [torneo for torneo in lista_de_torneos if now < torneo.fechaInicio]
    torneos_finalizados = [torneo for torneo in lista_de_torneos if torneo.fechaFin < now]

    return render_template(
        "listaTorneos.html",
        torneos_activos=torneos_activos,
        torneos_inactivos=torneos_inactivos,
        torneos_finalizados=torneos_finalizados
    )


@app.route('/listaTorneos/crear-torneo', methods=['POST'])
@requiere_admin
def crearTorneo():
    buscar_torneo = database.session.query(Torneos).filter_by(nombreTorneo=request.form['nombreTorneo']).first()
    if buscar_torneo:
        flash(f'El torneo: {buscar_torneo.nombreTorneo} ya ha sido registrado.')
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: El torneo: {buscar_torneo.nombreTorneo} ya ha sido registrado.","ERROR")
        return redirect(url_for('listar_torneos'))

    nombreTorneo = request.form['nombreTorneo']
    nombreJuego = request.form['nombreJuego']
    limite_participantes = request.form.get('limiteParticipantes', type=int)
    try:
        # Convertir fechas
        fecha_inicio = datetime.strptime(request.form['fechaInicio'], "%Y-%m-%dT%H:%M")
        fecha_fin = datetime.strptime(request.form['fechaFin'], "%Y-%m-%dT%H:%M")
        inicio_inscripcion = datetime.strptime(request.form['inicioInscripcion'], "%Y-%m-%dT%H:%M")
        cierre_inscripcion = datetime.strptime(request.form['cierreInscripcion'], "%Y-%m-%dT%H:%M")

    except ValueError as e:
        # Si las fechas no son válidas, redirigir con error
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
        flash("Por favor, introduce unas fechas válidas", "error")
        return redirect(url_for('listar_torneos', error="Fechas inválidas."))

    # Validar lógica de fechas
    if (
        fecha_inicio >= fecha_fin or
        inicio_inscripcion >= cierre_inscripcion or
        cierre_inscripcion >= fecha_inicio
    ):
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: Error en la logica de las fechas", "ERROR")
        flash("Error en la lógica de las fechas", "error")
        return redirect(url_for('listar_torneos', error="Error en la lógica de fechas."))

    # Crear torneo con el campo 'ganador' vacío
    try:
        torneo = Torneos(
            nombreTorneo=nombreTorneo,
            nombreJuego=nombreJuego,
            fechaInicio=fecha_inicio,
            fechaFin=fecha_fin,
            inicioInscripcion=inicio_inscripcion,
            cierreInscripcion=cierre_inscripcion,
            limiteParticipantes=limite_participantes,
            ganador=""  # Inicializar el campo como vacío
        )
        database.session.add(torneo)
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha creado correctamente el torneo {torneo.nombreTorneo}","WARN")
        flash("Torneo creado correctamente", "success")
        database.session.commit()
    except Exception as e:
        flash("Hubo problemas al crear el torneo", "error")
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
        database.session.rollback()
        return redirect(url_for('listar_torneos'))

    return redirect(url_for('listar_torneos'))


@app.route('/listaTorneos/borrar-torneo/<id>')
@requiere_admin
def borrar_torneo(id):
    # Obtener el torneo antes de eliminarlo
    torneo = database.session.query(Torneos).filter_by(id=id).first()
    if torneo:
        nombre_torneo = torneo.nombreTorneo  # Guardar el nombre del torneo antes de eliminar
        try:
            # Eliminar el torneo
            database.session.query(Torneos).filter_by(id=id).delete()
            # Eliminar los participantes asociados
            database.session.query(Participantes).filter_by(nombreTorneo=nombre_torneo).delete()
            # Confirmar los cambios
            database.session.commit()
            flash("Torneo borrado con éxito", "success")
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha borrado el torneo {nombre_torneo}", "INFO")
        except Exception as e:
            flash("Hubo problemas para borrar el torneo", "error")
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
            database.session.rollback()
    else:
        # Manejar caso en el que el torneo no exista
        flash("El torneo no existe o ya fue eliminado", "warning")
    return redirect(url_for('listar_torneos'))


@app.route('/listaTorneos/editar-torneo/<id>', methods=['POST', 'GET'])
@requiere_admin
def editar_torneo(id):
    seleccion_torneo = database.session.query(Torneos).filter_by(id=id).first()
    if not seleccion_torneo:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: Error al seleccionar torneo con id: {id}.", "ERROR")
        return redirect(url_for('listar_torneos'))

    if request.method == 'POST':
        errores = []
        datos_actualizados = {}

        # Obtener datos del formulario
        nuevo_nombreTorneo = request.form.get('nombreTorneo')
        nuevo_nombreJuego = request.form.get('nombreJuego')
        nuevo_limite = request.form.get('limiteParticipantes', type=int)
        nuevo_fecha_inicio = request.form.get('fechaInicio')
        nuevo_fecha_fin = request.form.get('fechaFin')
        nuevo_inicio_inscripcion = request.form.get('inicioInscripcion')
        nuevo_cierre_inscripcion = request.form.get('cierreInscripcion')
        nuevo_ganador = request.form.get('ganador')  # Obtener el ganador

        try:
            if nuevo_fecha_inicio:
                datos_actualizados['fechaInicio'] = datetime.strptime(nuevo_fecha_inicio, "%Y-%m-%dT%H:%M")
            if nuevo_fecha_fin:
                datos_actualizados['fechaFin'] = datetime.strptime(nuevo_fecha_fin, "%Y-%m-%dT%H:%M")
            if nuevo_inicio_inscripcion:
                datos_actualizados['inicioInscripcion'] = datetime.strptime(nuevo_inicio_inscripcion, "%Y-%m-%dT%H:%M")
            if nuevo_cierre_inscripcion:
                datos_actualizados['cierreInscripcion'] = datetime.strptime(nuevo_cierre_inscripcion, "%Y-%m-%dT%H:%M")

            fecha_inicio = datos_actualizados.get('fechaInicio', seleccion_torneo.fechaInicio)
            fecha_fin = datos_actualizados.get('fechaFin', seleccion_torneo.fechaFin)
            inicio_inscripcion = datos_actualizados.get('inicioInscripcion', seleccion_torneo.inicioInscripcion)
            cierre_inscripcion = datos_actualizados.get('cierreInscripcion', seleccion_torneo.cierreInscripcion)

            if fecha_inicio >= fecha_fin:
                flash("La fecha de inicio debe ser anterior a la fecha de fin del torneo.", "error")
                errores.append("Error, la fecha de inicio debe ser anterior a la fecha de fin del torneo.")
            if inicio_inscripcion >= cierre_inscripcion:
                flash("La fecha de inicio de inscripción debe ser anterior a la fecha de cierre.", "error")
                errores.append("Error, la fecha de inicio de inscripción debe ser anterior a la fecha de cierre.")
            if cierre_inscripcion >= fecha_inicio:
                flash("El cierre de inscripciones debe ser anterior a la fecha de inicio del torneo.", "error")
                errores.append("Error, el cierre de inscripciones debe ser anterior a la fecha de inicio del torneo.")
        except ValueError as e:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")

        # Validar y agregar otros campos
        if nuevo_nombreJuego:
            datos_actualizados['nombreJuego'] = nuevo_nombreJuego
        if nuevo_nombreTorneo:
                datos_actualizados['nombreTorneo'] = nuevo_nombreTorneo
        if nuevo_limite and nuevo_limite > 0:
            datos_actualizados['limiteParticipantes'] = nuevo_limite
        if nuevo_ganador and fecha_fin < datetime.now():
            datos_actualizados['ganador'] = nuevo_ganador

        if errores:
            for error in errores:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {error}", "ERROR")
            return render_template('editarTorneo.html', torneo=seleccion_torneo)

        if datos_actualizados:
            for campo, valor in datos_actualizados.items():
                setattr(seleccion_torneo, campo, valor)
        else:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se actualizó sin cambios el torneo {seleccion_torneo.nombreTorneo}", "INFO")
            flash(f"No se realizó ningún cambio sobre el torneo: {seleccion_torneo.nombreTorneo}", "warning")
            database.session.rollback()
            return redirect(url_for('listar_torneos'))
        try:
            if nuevo_nombreTorneo:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha modificado el torneo {seleccion_torneo.nombreTorneo} -> {nuevo_nombreTorneo}","INFO")
            else:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Se ha modificado el torneo {seleccion_torneo.nombreTorneo}", "INFO")
            flash("Torneo actualizado correctamente", "success")
            database.session.commit()
            return redirect(url_for('listar_torneos'))
        except Exception as e:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
            flash("Hubo problemas para modificar el torneo", "error")
            database.session.rollback()

    return render_template('editarTorneo.html', torneo=seleccion_torneo)

@app.route('/listaTorneos/<nombreTorneo>/finalizar', methods=['GET'])
@requiere_admin
def finalizar_torneo(nombreTorneo):
    # Obtener el torneo
    torneo = database.session.query(Torneos).filter_by(nombreTorneo=nombreTorneo).first()
    if not torneo:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: Error al seleccionar torneo: {nombreTorneo}.", "ERROR")
        flash(f"Torneo '{nombreTorneo}' no encontrado.", "error")
        return redirect(url_for('listar_torneos'))

    # Validar que el torneo haya finalizado
    if datetime.now() < torneo.fechaFin:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: El torneo '{nombreTorneo}' aún no ha finalizado.", "ERROR")
        flash(f"El torneo '{nombreTorneo}' aún no ha finalizado.", "error")
        return redirect(url_for('listar_torneos'))

    # Validar si el torneo ya tiene un ganador registrado
    if torneo.ganador:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: El torneo '{nombreTorneo}' ya tiene un ganador registrado: {torneo.ganador}.", "ERROR")
        flash(f"El torneo '{nombreTorneo}' ya tiene un ganador registrado: {torneo.ganador}.", "warning")
        return redirect(url_for('listar_torneos'))

    # Obtener los participantes con la máxima puntuación
    max_puntuacion = (
        database.session.query(func.max(Participantes.puntuacion))
        .filter(Participantes.nombreTorneo == nombreTorneo)
        .scalar()
    )

    if max_puntuacion is None:
        # No hay participantes registrados
        torneo.ganador = "Sin ganador"
        try:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: No hay participantes registrados en el torneo '{nombreTorneo}'. Se registra como 'Sin ganador'.","ERROR")
            flash(f"No hay participantes registrados en el torneo '{nombreTorneo}'. Se registra como 'Sin ganador'.","warning")
            database.session.commit()
        except Exception as e:
            database.session.rollback()
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}","ERROR")
            flash(f"Error al registrar el estado del torneo: {str(e)}", "error")
        return redirect(url_for('listar_torneos'))

    # Obtener a todos los participantes con la máxima puntuación
    ganadores = (
        database.session.query(Participantes)
        .filter(Participantes.nombreTorneo == nombreTorneo, Participantes.puntuacion == max_puntuacion)
        .all()
    )

    if len(ganadores) == 1:
        # Un único ganador
        torneo.ganador = ganadores[0].usuario
        mensaje = f"El ganador del torneo '{nombreTorneo}' es {ganadores[0].usuario} con {max_puntuacion} puntos."
    else:
        # Múltiples ganadores (empate)
        nombres_ganadores = ", ".join(g.usuario for g in ganadores)
        torneo.ganador = f"Empate: {nombres_ganadores}"
        mensaje = f"El torneo '{nombreTorneo}' terminó en empate entre: {nombres_ganadores} con {max_puntuacion} puntos."

    # Registrar el resultado
    try:
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {mensaje}", "INFO")
        flash(mensaje, "success")
    except Exception as e:
        database.session.rollback()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
        flash(f"Error al registrar el resultado del torneo: {str(e)}", "error")

    return redirect(url_for('listar_torneos'))

"""
OPERACIONES CON PARTICIPANTES
"""
# Lista de participantes
@app.route('/listaParticipantes')
@requiere_admin
def listar_participantes():
    now = datetime.now()
    lista_de_participantes = database.session.query(Participantes).join(
        Torneos, Torneos.nombreTorneo == Participantes.nombreTorneo
    ).filter(Torneos.fechaFin >= now).order_by(Participantes.nombreTorneo, Participantes.usuario, Participantes.categoria).all()
    lista_de_usuarios = database.session.query(Usuarios).order_by(Usuarios.usuario).all()
    lista_de_torneos = database.session.query(Torneos).filter(and_(Torneos.inicioInscripcion <= now, Torneos.cierreInscripcion >= now)).order_by(Torneos.nombreTorneo).all()
    return render_template("listaParticipantes.html", lista_de_participantes=lista_de_participantes, lista_de_usuarios=lista_de_usuarios, lista_de_torneos=lista_de_torneos)

@app.route('/listaParticipantes/crear-participante', methods=['POST'])
@requiere_admin
def crear_participante():
    # Validar datos del formulario
    usuario = request.form.get('usuario')
    nombreTorneo = request.form.get('nombreTorneo')
    categoria = request.form.get('categoria')

    if not usuario or not nombreTorneo or not categoria:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: Datos incompletos para crear participante","ERROR")
        flash("Datos incompletos para crear participante", "error")
        return redirect(url_for('listar_participantes', error="Datos incompletos para crear participante."))

    # Buscar el torneo
    torneo = database.session.query(Torneos).filter_by(nombreTorneo=nombreTorneo).first()
    if not torneo:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: No existe un torneo al que añadir al participante","ERROR")
        flash("El torneo al que añadir al participante no existe", "error")
        return redirect(url_for('listar_participantes', error="Torneo no encontrado."))

    # Contar participantes en la categoría
    participantes_actuales = (
        database.session.query(Participantes)
        .filter_by(nombreTorneo=nombreTorneo, categoria=categoria)
        .count()
    )
    max_participantes = torneo.limiteParticipantes

    if participantes_actuales >= max_participantes:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: No hay plazas disponibles en esta categoría.","ERROR")
        flash("No hay plazas disponibles en esta categoría.","error")
        return redirect(url_for('listar_participantes'))

    # Revisar que el usuario no este inscrito ya al torneo
    buscar_participante = database.session.query(Participantes).filter(and_(Participantes.usuario == usuario, Participantes.nombreTorneo == nombreTorneo)).first()
    if buscar_participante:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: El usuario {usuario} ya participa en el torneo {nombreTorneo}.","ERROR")
        flash(f"El usuario {usuario} ya participa en ese torneo.","error")
        return redirect(url_for('listar_participantes'))

    # Crear participante si hay espacio
    participante = Participantes(
        usuario=usuario,
        nombreTorneo=nombreTorneo,
        categoria=categoria,
        puntuacion=0
    )
    try:
        database.session.add(participante)
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - El usuario {usuario} ha sido inscrito en el torneo {nombreTorneo}, en la categoria {categoria}.","INFO")
        flash("Participante creado correctamente", "success")
        return redirect(url_for('listar_participantes'))
    except Exception as e:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
        flash("Hubo problemas al crear el usuario", "error")
        database.session.rollback()
        return redirect(url_for('listar_participantes'))


@app.route('/listaParticipantes/borrar-participante/<id>')
@requiere_admin
def borrar_participante(id):
    participante = database.session.query(Participantes).filter_by(id=id).first()
    nombreParticipante = participante.usuario
    nombreTorneo = participante.nombreTorneo
    database.session.query(Participantes).filter_by(id=id).delete()
    try:
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Ha eliminado la inscripcion del participante {nombreParticipante} al torneo {nombreTorneo}", "INFO")
        flash(f"Participante {nombreParticipante} eliminado correctamente del torneo {nombreTorneo}", "success")
    except Exception as e:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
        flash("No se pudo borrar el participante", "error")
        database.session.rollback()
    return redirect(url_for('listar_participantes'))

@app.route('/actualizar-puntuaciones/<nombreTorneo>', methods=['POST'])
@requiere_admin
def actualizar_puntuaciones(nombreTorneo):
    # Comprobar que el usuario tiene acceso de administrador
    if session.get('acceso') != 'admin':
        abort(403)  # Prohibido, no tiene permisos

    # Leer las puntuaciones enviadas desde el formulario
    puntuaciones_actualizadas = request.form.to_dict(flat=True)

    # Comprobar que hay datos enviados
    if not puntuaciones_actualizadas:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: No se enviaron datos para actualizar las puntuaciones.","ERROR")
        flash("No se enviaron datos para actualizar.", "error")
        return redirect(url_for('mostrar_grafico_categoria_simple', nombreTorneo=nombreTorneo))

    # Actualizar cada puntuación en la base de datos
    for usuario, puntuacion in puntuaciones_actualizadas.items():
        try:
            participante = (
                database.session.query(Participantes)
                .filter_by(nombreTorneo=nombreTorneo, usuario=usuario)
                .first()
            )
            if participante:
                participante.puntuacion = int(puntuacion)  # Actualizar la puntuación
        except ValueError as e:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
            flash(f"Error al procesar la puntuación para el usuario {usuario}: {str(e)}", "error")
        except Exception as e:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
            flash(f"Error general al actualizar para el usuario {usuario}: {str(e)}", "error")

    # Confirmar cambios en la base de datos
    try:
        database.session.commit()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Puntuaciones actualizadas correctamente.","INFO")
        flash("Puntuaciones actualizadas correctamente.", "success")
    except Exception as e:
        database.session.rollback()
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
        flash(f"Error al confirmar cambios en la base de datos: {str(e)}", "error")

    # Redirigir nuevamente a la página del gráfico
    return redirect(url_for('mostrar_grafico_categoria_simple', nombreTorneo=nombreTorneo))

#··········································#
# OPERACIONES PARA AMBOS TIPOS DE USUARIOS #
#··········································#

@app.route('/session/lista-de-torneos/<estado>', methods=['POST', 'GET'])
@requiere_usuario
def mostrar_torneos(estado):
    now = datetime.now()
    # Determinar el filtro según el estado
    if estado == "activos":
        filtro_estado = and_(Torneos.fechaInicio <= now, Torneos.fechaFin >= now)
    elif estado == "finalizados":
        filtro_estado = Torneos.fechaFin < now
    else:
        abort(404)  # Estado inválido

    # Filtrar torneos según el estado
    if request.method == 'POST':
        nombreJuego = request.form.get('nombreJuego')
        if nombreJuego:
            lista_de_torneos = (
                database.session.query(Torneos)
                .filter(Torneos.nombreJuego == nombreJuego, filtro_estado)
                .order_by(Torneos.nombreTorneo)
                .all()
            )
        else:
            lista_de_torneos = (
                database.session.query(Torneos)
                .filter(filtro_estado)
                .order_by(Torneos.nombreTorneo)
                .all()
            )
    else:
        lista_de_torneos = (
            database.session.query(Torneos)
            .filter(filtro_estado)
            .order_by(Torneos.nombreTorneo)
            .all()
        )

    # Obtener los juegos únicos según el estado
    lista_de_juegos = (
        database.session.query(Torneos.nombreJuego)
        .filter(filtro_estado)
        .distinct()
        .order_by(Torneos.nombreJuego)
        .all()
    )

    return render_template(
        'lista_de_torneos.html',
        lista_de_juegos=lista_de_juegos,
        lista_de_torneos=lista_de_torneos,
        estado=estado
    )

@app.route('/torneo/<nombreTorneo>/grafico', methods=['GET', 'POST'])
@requiere_usuario
def mostrar_grafico_categoria_simple(nombreTorneo):
    # Obtener categorías únicas del torneo
    categorias = (
        database.session.query(Participantes.categoria)
        .filter(Participantes.nombreTorneo == nombreTorneo)
        .distinct()
        .all()
    )
    categorias = [c[0] for c in categorias]  # Convertir a lista simple en lugar de tupla

    categoria_seleccionada = None
    participantes = []

    if request.method == 'POST':
        # Obtener la categoría seleccionada
        categoria_seleccionada = request.form.get('categoria')

        if categoria_seleccionada:
            # Filtrar participantes por categoría seleccionada
            participantes = (
                database.session.query(Participantes.usuario, Participantes.puntuacion)
                .filter(
                    Participantes.nombreTorneo == nombreTorneo,
                    Participantes.categoria == categoria_seleccionada
                )
                .order_by(Participantes.puntuacion.desc())
                .all()
            )

    # Verificar si el usuario es administrador usando la sesión
    user_admin = session.get('acceso') == 'admin'

    # Verificar el estado del torneo
    torneo = database.session.query(Torneos).filter(Torneos.nombreTorneo == nombreTorneo).first()
    if datetime.now() > torneo.fechaFin:
        estado = 'Finalizado'
    else:
        estado = ''

    return render_template(
        'grafico.html',
        nombre_torneo=nombreTorneo,
        categorias=categorias,
        categoria_seleccionada=categoria_seleccionada,
        participantes=participantes,
        user_admin=user_admin,
        estado = estado
    )

@app.route('/session/lista-de-inscripciones', methods=['POST', 'GET'])
@requiere_usuario
def mostrar_inscripciones_activas():
    # Obtén la fecha y hora actual para filtrar inscripciones activas
    now = datetime.now()

    if request.method == 'POST':
        # Filtrar por el nombre del juego, si es proporcionado
        nombreJuego = request.form.get('nombreJuego')
        if nombreJuego:
            lista_de_torneos = (
            database.session.query(Torneos)
            .join(Participantes, Torneos.nombreTorneo == Participantes.nombreTorneo)
            .filter(and_(Torneos.inicioInscripcion <= now, Torneos.cierreInscripcion >= now, Participantes.usuario != session['usuario']))  # Inscripciones activos
            .order_by(Torneos.nombreTorneo)
            .all()
        )
            torneos_de_inscritos = (
                database.session.query(Torneos)
                .join(Participantes, Torneos.nombreTorneo == Participantes.nombreTorneo)
                .filter(
                    and_(
                        Participantes.usuario == session['usuario'],
                        Torneos.nombreJuego == nombreJuego,
                        Torneos.fechaFin > now
                    )
                )
                .order_by(Torneos.nombreTorneo)
                .all()
            )
        else:
            # Si no se selecciona un juego, solo muestra los torneos activos
            # Torneos con inscripción activa y donde el usuario NO esté inscrito
            lista_de_torneos = (
                database.session.query(Torneos)
                .filter(
                    and_(
                        Torneos.inicioInscripcion <= now,
                        Torneos.cierreInscripcion >= now,
                        ~Torneos.nombreTorneo.in_(database.session.query(Participantes.nombreTorneo).filter(Participantes.usuario == session['usuario']))))
                .order_by(Torneos.nombreTorneo).all()
            )

            # Torneos donde el usuario YA está inscrito
            torneos_de_inscritos = (
                database.session.query(Torneos)
                .join(Participantes, Torneos.nombreTorneo == Participantes.nombreTorneo)
                .filter(and_(
                    Participantes.usuario == session['usuario'],
                    Torneos.fechaFin > now
                ))
                .order_by(Torneos.nombreTorneo)
                .all()
            )
    else:
        # Solicitud GET: Mostrar todos los torneos activos
        # Torneos con inscripción activa y donde el usuario NO esté inscrito
        lista_de_torneos = (
            database.session.query(Torneos)
            .filter(
                and_(
                    Torneos.inicioInscripcion <= now,
                    Torneos.cierreInscripcion >= now,
                    ~Torneos.nombreTorneo.in_(
                        database.session.query(Participantes.nombreTorneo).filter(
                            Participantes.usuario == session['usuario']
                        )
                    )
                )
            )
            .order_by(Torneos.nombreTorneo)
            .all()
        )

        # Torneos donde el usuario YA está inscrito
        torneos_de_inscritos = (
            database.session.query(Torneos)
            .join(Participantes, Torneos.nombreTorneo == Participantes.nombreTorneo)
            .filter(and_(
                Participantes.usuario == session['usuario'],
                Torneos.fechaFin > now
            ))
            .order_by(Torneos.nombreTorneo)
            .all()
        )

    # Lista de juegos únicos con inscripciones activas
    lista_de_juegos = (
        database.session.query(Torneos.nombreJuego)
        .filter(and_(Torneos.inicioInscripcion <= now, Torneos.cierreInscripcion >= now))  # Juegos con inscripciones activos
        .distinct()
        .order_by(Torneos.nombreJuego)
        .all()
    )

    # Renderiza la plantilla con las listas de torneos y juegos
    return render_template(
        'lista_de_inscripciones.html',
        lista_de_juegos=lista_de_juegos,
        lista_de_torneos=lista_de_torneos,
        torneos_inscritos = torneos_de_inscritos
    )


@app.route('/session/lista-de-inscripciones/inscripcion/<nombreTorneo>', methods=['POST', 'GET'])
@requiere_usuario
def inscribirse(nombreTorneo):
    busqueda_torneo = database.session.query(Torneos).filter_by(nombreTorneo=nombreTorneo).first()
    if busqueda_torneo:
        categorias = ['amateur', 'normal', 'experto']

        query = (
            database.session.query(
                Participantes.categoria,
                func.count(Participantes.categoria).label('participantes_totales')
            )
            .filter(Participantes.categoria.in_(categorias), Participantes.nombreTorneo == nombreTorneo)
            .group_by(Participantes.categoria)
        )
        resultados = query.all()

        resultados_dict = {r.categoria: r.participantes_totales for r in resultados}
        for categoria in categorias:
            if categoria not in resultados_dict:
                resultados_dict[categoria] = 0

        resultados = [{'categoria': k, 'participantes_totales': v} for k, v in resultados_dict.items()]
        limite_participantes = database.session.query(Torneos.limiteParticipantes).filter_by(
            nombreTorneo=nombreTorneo).scalar()

        if request.method == 'POST':
            categoria_seleccionada = request.form.get('categoria')
            if categoria_seleccionada:
                total_participantes = (
                    database.session.query(func.count(Participantes.id))
                    .filter_by(nombreTorneo=nombreTorneo, categoria=categoria_seleccionada)
                    .scalar()
                )
                if total_participantes < busqueda_torneo.limiteParticipantes:
                    nuevo_participante = Participantes(
                        usuario=session['usuario'],
                        nombreTorneo=nombreTorneo,
                        categoria=categoria_seleccionada,
                        puntuacion=0
                    )
                    try:
                        database.session.add(nuevo_participante)
                        database.session.commit()
                        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: El usuario {nuevo_participante.usuario} ha sido inscrito en el torneo {nuevo_participante.nombreTorneo}, en la categoria {nuevo_participante.categoria}.","INFO")
                        flash("Inscripción completada con éxito", "success")
                    except Exception as e:
                        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
                        database.session.rollback()
                else:
                    escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: Intentó inscribirse al torneo {nombreTorneo} pero no hay plazas disponibles en la categoria {categoria_seleccionada}","ERROR")
                    flash("No hay plazas disponibles en la categoría seleccionada", "error")
            else:
                escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Exception: No se ha seleccionado una categoria","ERROR")
                flash("Debe seleccionar una categoría", "warning")
            return redirect(url_for('mostrar_inscripciones_activas'))

        return render_template('inscripcion.html', resultados=resultados, limite=limite_participantes,torneo=busqueda_torneo)
    else:
        return redirect(url_for('mostrar_inscripciones_activas'))

@app.route('/session/lista-de-inscripciones/borrar-inscripcion/<nombreTorneo>')
@requiere_usuario
def borrar_inscripcion(nombreTorneo):
    now = datetime.now()
    torneo = database.session.query(Torneos).filter(Participantes.nombreTorneo == nombreTorneo).first()
    if now < torneo.fechaInicio:
        database.session.query(Participantes).filter(and_(Participantes.nombreTorneo == nombreTorneo, Participantes.usuario == session['usuario'])).delete()
        try:
            database.session.commit()
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - Ha borrado su inscripción al torneo {nombreTorneo}","INFO")
            flash("Has borrado tu inscripción correctamente", "success")
        except Exception as e:
            escribir_log(f"[{session['acceso']}] [{session['usuario']}] - {str(e)}", "ERROR")
            flash("No ha sido posible borrar tu inscripción", "error")
            database.session.rollback()
    else:
        escribir_log(f"[{session['acceso']}] [{session['usuario']}] - El torneo {nombreTorneo} ya ha iniciado, imposible borrar inscripcion", "ERROR")
        flash(f"No ha sido posible borrar tu inscripción, el torneo {nombreTorneo} ya ha comenzado", "error")
    return redirect(url_for('mostrar_inscripciones_activas'))

if __name__ == '__main__':
    database.Base.metadata.create_all(database.engine)
    escribir_log(f"Iniciando sistema...", "INFO")
    generar_admin()
    app.run(debug=True)
    #app.run(debug=True, use_reloader=False) # Desactivar la recarga automatica debug de Flask para monitorizar los cambios en el codigo mientras el servicio está activo