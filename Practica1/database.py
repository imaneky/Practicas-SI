import sqlite3
import csv
import json
import pandas as pd


#########################################
# DEFINICION DE FUNCIONES
#########################################

def createDB():
    try:
        conexion = sqlite3.connect('alerts_database.db')
        c = conexion.cursor()
        c.execute('CREATE TABLE IF NOT EXISTS alerts(timestamp date, sid real, msg text, clasificacion text, '
                  'prioridad real, protocolo text, origen text, destino text, puerto real) ')
        c.execute('CREATE TABLE IF NOT EXISTS devices(id text, ip text, localizacion text, responsableNombre text, '
                  'responsableTlfn integer, responsableRol text, analisisPuertosAbiertos text, analisisServicios integer, '
                  'analisisServiviosInseguros integer, analisisVulnerabilidades integer )')
        conexion.close()
    except Exception as execption:
        print(execption)


def missingCero(originalValue):
    value = 'NULL'
    if originalValue != "None":
        value = originalValue
    return value


def loadCSV():
    with open('alerts.csv') as alertsCSV:
        alertsFile = csv.DictReader(alertsCSV)
        alertsCSV.close()
        for i in alertsFile:
            insertAlerts((i['timestamp'], i['sid'], i['msg'], i['clasificacion'], i['prioridad'], i['protocolo'],
                          i['origen'], i['destino'], i['puerto']))


def loadJSON():
    file = open("devices.json")
    devicesFile = json.load(file)
    file.close()
    for i in devicesFile:
        insertDevices((missingCero(i['id']), missingCero(i['ip']), missingCero(i['localizacion']),
                       missingCero(i['responsable']['nombre']), missingCero(i['responsable']['telefono']),
                       missingCero(i['responsable']['rol']), missingCero(str(i['analisis']['puertos_abiertos'])),
                       missingCero(i['analisis']['servicios']), missingCero(i['analisis']['servicios_inseguros']),
                       missingCero(i['analisis']['vulnerabilidades_detectadas'])))


def insertDevices(variables):
    conexion = sqlite3.connect('alerts_database.db')
    c = conexion.cursor()
    c.execute('INSERT INTO devices(id,ip,localizacion,responsableNombre,responsableTlfn,responsableRol,'
              'analisisPuertosAbiertos,analisisServicios,analisisServiviosInseguros,analisisVulnerabilidades) '
              'VALUES (?,?,?,?,?,?,?,?,?,?)', variables)
    conexion.commit()
    conexion.close()


def insertAlerts(variables):
    conexion = sqlite3.connect('alerts_database.db')
    c = conexion.cursor()
    c.execute('INSERT INTO alerts(timestamp,sid,msg,clasificacion,prioridad,protocolo,origen,destino,puerto)'
              'VALUES (?,?,?,?,?,?,?,?,?)', variables)
    conexion.commit()
    conexion.close()


def deleteDB():
    conexion = sqlite3.connect('alerts_database.db')
    c = conexion.cursor()
    c.execute('DROP TABLE IF EXISTS alerts')
    conexion.commit()
    c.execute('DROP TABLE IF EXISTS devices')
    conexion.commit()
    conexion.close()


deleteDB()
createDB()
print("DB creada")

loadJSON()
print("JSON cargado")

loadCSV()
print('CSV cargado')
