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


@app.route('/')
def index():
    # Get the JSON data for the initial chart
    chartIPJSON = chart_IP(numIP)
    chartDevicesJSON = chart_devices(numDevice)
    chartDangerousJSON = chart_dangerous(numPeligrosos)
    chartSecureJSON = chart_secure(numSeguros)
    chartTotalSecurityJSON = chart_total_security()

    return render_template('index.html', chartIPJSON=chartIPJSON, numIP=numIP,
                           chartDevicesJSON=chartDevicesJSON, numDevice=numDevice,
                           chartDangerousJSON=chartDangerousJSON, numPeligrosos=numPeligrosos,
                           chartSecureJSON=chartSecureJSON, numSeguros=numSeguros,
                           chartTotalSecurityJSON=chartTotalSecurityJSON,
                           vulnerabilidades=vulnerabilidades, last_updated_cve=last_updated_cve)


@app.route('/chart_IP/<int:num>')
def chart_IP(num):
    global numIP
    numIP = num
    ip_mas_problematicas_df = alerts_df[alerts_df['prioridad'] == 1]
    ip_mas_problematicas_df = ip_mas_problematicas_df.groupby('origen')['sid'].count().reset_index(name='numero_alertas')
    #ip_mas_problematicas_counts = ip_mas_problematicas_df['origen'].value_counts().head(numIP)
    ip_mas_problematicas_df.sort_values(by=['numero_alertas'], ascending=False, inplace=True)

    fig = px.bar(ip_mas_problematicas_df.head(numIP), x='origen', y='numero_alertas', barmode='group',labels=dict(origen="IP", numero_alertas="Número de alertas"))
    #fig = px.bar(x=ip_mas_problematicas_df.index, y=ip_mas_problematicas_counts.values, labels={'x': 'IP', 'y': 'Nº de alertas'})

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return chartJSON


@app.route('/chartDevices/<int:num>')
def chart_devices(num):
    global numDevice
    numDevice = num
    dispositivos_vulnerables_df = devices_df.groupby('id')['numero_vulnerabilidades'].sum().reset_index(name='numero_vulnerabilidades')
    dispositivos_vulnerables_df.sort_values(by=['numero_vulnerabilidades'], ascending=False, inplace=True)
    fig = px.bar(dispositivos_vulnerables_df.head(numDevice), x='id', y='numero_vulnerabilidades', barmode='group',labels=dict(id="Dispositivo", numero_vulnerabilidades="Número de vulnerabilidades"))

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

    fig = px.pie(df, values='Cantidad', names='Estado', title='Dispositivos Seguros vs. Peligrosos')

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


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


if __name__ == '__main__':

    vulnerabilidades_cve()
    app.run(port=80, debug=True)

