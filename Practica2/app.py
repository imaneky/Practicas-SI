import json
import tempfile
from flask import Flask, render_template, jsonify, abort, make_response
from flask_bootstrap import Bootstrap
import sqlite3
import pandas as pd
import plotly.express as px
import plotly
import requests
import datetime
from apscheduler.schedulers.background import BackgroundScheduler
import plotly.io as pio
import os
from flask_weasyprint import HTML, render_pdf
import kaleido
import uuid
import os



app = Flask(__name__)

con = sqlite3.connect('../Practica1/alerts_database.db')
cur = con.cursor()
alerts_df = pd.read_sql_query("SELECT * from alerts", con)
devices_df = pd.read_sql_query(
    "SELECT id, SUM(analisisServiviosInseguros + analisisVulnerabilidades) as numero_vulnerabilidades FROM DEVICES GROUP BY id ORDER BY numero_vulnerabilidades ",
    con)
df_devices = pd.read_sql_query("SELECT * from devices", con)
vulnerabilidades = []
last_updated_cve = ""
numIP = 10
numDevice = 5
numPeligrosos = 3
numSeguros = 3

def colorPalette():
    return ['#FF7F50'] * 50

@app.route('/')
def index():
    # Get the JSON data for the initial chart
    chartIPJSON = chart_IP(numIP)
    chartDevicesJSON = chart_devices(numDevice)
    chartDangerousJSON = chart_dangerous(numPeligrosos)
    chartSecureJSON = chart_secure(numSeguros)
    chartTotalSecurityJSON = chart_total_security()
    vulnerabilities_table, counter = update_vulnerabilities_table()
    counter_response = requests.get("http://localhost/get_counter")
    counter_data = counter_response.json()
    counter = counter_data['counter']

    return render_template('index.html', chartIPJSON=chartIPJSON, numIP=numIP,
                           chartDevicesJSON=chartDevicesJSON, numDevice=numDevice,
                           chartDangerousJSON=chartDangerousJSON, numPeligrosos=numPeligrosos,
                           chartSecureJSON=chartSecureJSON, numSeguros=numSeguros,
                           chartTotalSecurityJSON=chartTotalSecurityJSON,
                           vulnerabilities_table=vulnerabilities_table, last_updated_cve=last_updated_cve,
                           counter=counter)


@app.route('/chart_IP/<int:num>')
def chart_IP(num):
    global numIP
    numIP = num
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')
    #ip_mas_problematicas_counts = ip_mas_problematicas_df['origen'].value_counts().head(numIP)
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', barmode='group',labels=dict(origen="IP", numero_alertas="Número de alertas"), color_discrete_sequence=colorPalette())
    #fig = px.bar(x=ip_mas_problematicas_df.index, y=ip_mas_problematicas_counts.values, labels={'x': 'IP', 'y': 'Nº de alertas'})

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return chartJSON


@app.route('/chartDevices/<int:num>')
def chart_devices(num):
    global numDevice
    numDevice = num
    dispositivos_vulnerables_df = devices_df.groupby('id')['numero_vulnerabilidades'].sum().reset_index(name='numero_vulnerabilidades')
    dispositivos_vulnerables_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_vulnerables_df.head(numDevice), x='id', y='numero_vulnerabilidades', barmode='group',labels=dict(id="Dispositivo", numero_vulnerabilidades="Número de vulnerabilidades"), color_discrete_sequence=colorPalette())

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartDangerous/<int:amount>')
def chart_dangerous(amount):
    global numPeligrosos
    numPeligrosos = amount
    dispositivos_peligrosos_df = devices_df[devices_df['numero_vulnerabilidades'] > 0]
    dispositivos_peligrosos_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_peligrosos_df.head(numPeligrosos), x='id', y='numero_vulnerabilidades', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº de vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartSecure/<int:amount>')
def chart_secure(amount):
    global numSeguros
    numSeguros = amount
    dispositivos_seguros_df = devices_df[devices_df['numero_vulnerabilidades'] == 0]
    dispositivos_seguros_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_seguros_df.head(numSeguros), x='id', y='numero_vulnerabilidades', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartTotalSecurity')
def chart_total_security():
    dispositivos_seguros_df = devices_df[devices_df['numero_vulnerabilidades'] == 0]
    dispositivos_peligrosos_df = devices_df[devices_df['numero_vulnerabilidades'] > 0]

    num_seguros = len(dispositivos_seguros_df)
    num_peligrosos = len(dispositivos_peligrosos_df)

    data = {'Estado': ['Seguros', 'Peligrosos'], 'Cantidad': [num_seguros, num_peligrosos]}
    df = pd.DataFrame(data)

    fig = px.pie(df, values='Cantidad', names='Estado', title='Dispositivos Seguros vs. Peligrosos', color_discrete_sequence=colorPalette())

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON

"""
def vulnerabilidades_cve():
    global vulnerabilidades
    global last_updated_cve

    response = requests.get("https://cve.circl.lu/api/last")

    if response.status_code == 200:
        data = response.json()
        data_sorted = sorted(data, key=lambda x: x['Published'], reverse=True)
        last_10_data = data_sorted[:10]
        vulnerabilidades = []

        for i in range(10):
            vulnerability = {"id": last_10_data[i]["id"], "summary": last_10_data[i]["summary"]}

            fecha_publicacion = datetime.datetime.fromisoformat(last_10_data[i]["Published"])
            vulnerability["fecha_publicacion"] = fecha_publicacion.strftime('%d-%m-%Y %H:%M')
            vulnerability["url"] = f"https://cve.circl.lu/cve/{last_10_data[i]['id']}"
            vulnerabilidades.append(vulnerability)

        last_updated_cve = datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S')
"""
def update_vulnerabilities_table():
    global vulnerabilities
    url = "https://cve.circl.lu/api/last/10"
    response = requests.get(url)
    vulnerabilities = response.json()

    # Crear una lista de diccionarios con los datos de las vulnerabilidades
    vulnerabilities_data = []
    for vulnerability in vulnerabilities:
        cve_id = vulnerability["id"]
        published_date = vulnerability["Published"]
        summary = vulnerability["summary"]
        vulnerabilities_data.append({"CVE ID": cve_id, "Fecha de publicación": published_date, "Resumen": summary})

    # Crear un DataFrame a partir de los datos de las vulnerabilidades
    vulnerabilities_df = pd.DataFrame(vulnerabilities_data)

    # Obtener la última vez que se actualizó la tabla de vulnerabilidades
    last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Limitar la tabla a las últimas 10 vulnerabilidades
    vulnerabilities_table = vulnerabilities_df.head(10).to_html(index=False)

    # Calcular el tiempo restante para el próximo refresh
    next_refresh = datetime.datetime.now() + datetime.timedelta(minutes=3)
    time_remaining = next_refresh - datetime.datetime.now()

    # Imprimir el contador pequeño arriba del tiempo restante
    counter = f"Actualización en: {time_remaining.seconds} segundos"

    # Actualizar las variables globales
    vulnerabilities = vulnerabilities_data
    global last_updated_cve
    last_updated_cve = last_updated

    return vulnerabilities_table, counter



# Programar la actualización de la tabla de vulnerabilidades cada 3 minutos
scheduler = BackgroundScheduler()
scheduler.add_job(update_vulnerabilities_table, 'interval', minutes=3)
scheduler.start()
@app.route('/get_counter')
def get_counter():
    vulnerabilities_table, counter = update_vulnerabilities_table()
    return jsonify(counter=counter)
@app.route('/get_vulnerabilities_table')
def get_vulnerabilities_table():
    vulnerabilities_table = update_vulnerabilities_table()
    return vulnerabilities_table

if __name__ == '__main__':

    update_vulnerabilities_table()
    app.run(port=80, debug=True)

