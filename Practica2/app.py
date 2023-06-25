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
from geopy.geocoders import Nominatim
from matplotlib import pyplot as plt
import folium
import chart



app = Flask(__name__)

con = sqlite3.connect('../Practica1/alerts_database.db')
cur = con.cursor()
alerts_df = pd.read_sql_query("SELECT * from alerts", con)
devices_df = pd.read_sql_query("SELECT id, SUM(analisisServiviosInseguros + analisisVulnerabilidades) as numero_vulnerabilidades FROM devices GROUP BY id ORDER BY numero_vulnerabilidades ", con)
df_devices = pd.read_sql_query("SELECT * from devices", con)
con_servicios_df = pd.read_sql_query("SELECT * FROM devices WHERE (analisisServicios>0)", con)

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
    vulnerabilities_table, counter = update_vulnerabilities_table()
    counter_response = requests.get("http://localhost/get_counter")
    counter_data = counter_response.json()
    counter = counter_data['counter']
    brechas_seguridad = obtener_brechas_de_seguridad()


    return render_template('index.html', chartIPJSON=chartIPJSON, numIP=numIP,
                           chartDevicesJSON=chartDevicesJSON, numDevice=numDevice,
                           chartDangerousJSON=chartDangerousJSON, numPeligrosos=numPeligrosos,
                           chartSecureJSON=chartSecureJSON, numSeguros=numSeguros,
                           vulnerabilities_table=vulnerabilities_table, last_updated_cve=last_updated_cve,
                           counter=counter, brechas_seguridad=brechas_seguridad)


@app.route('/chart_IP/<int:num>')
def chart_IP(num):
    global numIP
    numIP = num
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', barmode='group',labels=dict(origen="IP", numero_alertas="Número de alertas"), color_discrete_sequence=colorPalette())

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
    dangerous_df = con_servicios_df[con_servicios_df['analisisServiviosInseguros'] / con_servicios_df['analisisServicios'] > 0.33]
    dangerous_df.sort_values(by=['analisisVulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dangerous_df.head(numPeligrosos), x='id', y='analisisServicios', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº de vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/chartSecure/<int:amount>')
def chart_secure(amount):
    global numSeguros
    numSeguros = amount
    secure_df = con_servicios_df[con_servicios_df['analisisServiviosInseguros'] / con_servicios_df['analisisServicios'] < 0.33]
    secure_df.sort_values(by=['analisisVulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(secure_df.head(numSeguros), x='id', y='analisisServicios', barmode='group',
                 labels=dict(id="Dispositivo", numero_vulnerabilidades="Nº vulnerabilidades"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON





def update_vulnerabilities_table():
    global vulnerabilities
    url = "https://cve.circl.lu/api/last/10"
    response = requests.get(url)
    vulnerabilities = response.json()

    # Lista diccionario vulnerabilidades
    vulnerabilities_data = []
    for vulnerability in vulnerabilities:
        cve_id = vulnerability["id"]
        published_date = vulnerability["Published"]
        summary = vulnerability["summary"]
        vulnerabilities_data.append({"CVE ID": cve_id, "Fecha de publicación": published_date, "Resumen": summary})

    vulnerabilities_df = pd.DataFrame(vulnerabilities_data)

    # Last update
    last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    vulnerabilities_table = vulnerabilities_df.head(10).to_html(index=False)

    # Next refresh
    next_refresh = datetime.datetime.now() + datetime.timedelta(minutes=3)
    time_remaining = next_refresh - datetime.datetime.now()

    # Print counter
    counter = f"Actualizacion en: {time_remaining.seconds} segundos"

    vulnerabilities = vulnerabilities_data
    global last_updated_cve
    last_updated_cve = last_updated

    return vulnerabilities_table, counter

# Actualizacion
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

