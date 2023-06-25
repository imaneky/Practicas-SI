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

# -------------- EJERCICIO 4 --------------
#  Distribución de las clasificaciones de alertas más comunes
@app.route('/chartClassification/<int:num>')
def chartClassification(num):
    clasification_df = alerts_df.groupby('clasificacion')['sid'].count().reset_index(name='cantidad')
    clasification_df.sort_values(by=['cantidad'], ascending=False, inplace=True)

    fig = px.bar(clasification_df.head(num), x='clasificacion', y='cantidad',
                 labels=dict(clasificacion="Clasificación", cantidad="Cantidad"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON

@app.route('/securityBreaches')
def obtener_brechas_de_seguridad():
    url = 'https://haveibeenpwned.com/api/v3/breaches'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            brechas = response.json()
            return brechas
        else:
            print('Error en la solicitud:', response.status_code)
            return []
    except requests.RequestException as e:
        print('Error de conexión:', str(e))
        return []

#
@app.route('/chartTemporalEvolution')
def chartTemporalEvolution():

    alertas_por_fecha = alerts_df.groupby('timestamp').size().reset_index(name='cantidad')


    fig = px.line(alertas_por_fecha, x='timestamp', y='cantidad',
                  labels=dict(timestamp="Fecha", cantidad="Cantidad de Alertas"))

    chartJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
    return chartJSON


@app.route('/mapaDispositivos')
def mapaDispositivos():
    dispositivos_df = devices_df.copy()

    # Eliminar las filas que no tienen información de ubicación
    dispositivos_df = dispositivos_df[dispositivos_df['localizacion'] != 'None']

    # Obtener las coordenadas geográficas (latitud, longitud) de cada ubicación
    geolocator = Nominatim(user_agent="my_app")
    dispositivos_df['geolocation'] = dispositivos_df['localizacion'].apply(lambda x: geolocator.geocode(x))
    dispositivos_df['latitude'] = dispositivos_df['geolocation'].apply(lambda x: x.latitude if x else None)
    dispositivos_df['longitude'] = dispositivos_df['geolocation'].apply(lambda x: x.longitude if x else None)

    # Crear el mapa interactivo utilizando la biblioteca folium
    mapa = folium.Map(location=[dispositivos_df['latitude'].mean(), dispositivos_df['longitude'].mean()], zoom_start=4)

    # Agregar un marcador por cada dispositivo con información de ubicación
    for i, row in dispositivos_df.iterrows():
        if row['latitude'] and row['longitude']:
            folium.Marker([row['latitude'], row['longitude']], popup=row['localizacion']).add_to(mapa)

    # Guardar el mapa como un archivo HTML
    mapa_html = mapa.get_root().render()

    return mapa_html


def obtener_top_clasificaciones():
    alertas_categoria_df = alerts_df.groupby('clasificacion')['clasificacion'].count().reset_index(name='numero_alertas')
    alertas_categoria_df = alertas_categoria_df.sort_values(by='numero_alertas', ascending=False).head(3)

    return alertas_categoria_df


def obtener_informacion_wikipedia(clasificacion):
    url = f'https://es.wikipedia.org/w/api.php?action=opensearch&search={clasificacion}&limit=1&format=json'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            info = response.json()
            if len(info) > 2:
                return info[2][0]
            else:
                return ""
        else:
            return ""
    except requests.RequestException:
        return ""


def buscar_tweets(clasificacion):
    url = f'https://api.twitter.com/1.1/search/tweets.json?q={clasificacion}'

    try:
        response = requests.get(url)
        if response.status_code == 200:
            tweets = [tweet['text'] for tweet in response.json()['statuses']]
            return tweets
        else:
            return []
    except requests.RequestException:
        return []


@app.route('/chart_top_alertas')
def chart_top_alertas():
    top_clasificaciones = obtener_top_clasificaciones()
    clasificaciones = top_clasificaciones['clasificacion']
    porcentajes = top_clasificaciones['numero_alertas'] / top_clasificaciones['numero_alertas'].sum() * 100

    # Configurar el gráfico
    fig, ax = plt.subplots(figsize=(8, 8))
    wedges, _, autotexts = ax.pie(porcentajes, labels=clasificaciones, startangle=90,
                                  autopct='%1.1f%%', textprops={'fontsize': 'small'})
    ax.axis('equal')
    plt.title('Top 3 de Alertas')

    # Añadir porcentajes en el gráfico
    for autotext in autotexts:
        autotext.set_color('white')

    # Obtener información de Wikipedia y tweets para cada clasificación
    info_wikipedia = [obtener_informacion_wikipedia(clasificacion) for clasificacion in clasificaciones]
    tweets = [buscar_tweets(clasificacion) for clasificacion in clasificaciones]

    return jsonify({
        'grafico': plt,
        'info_wikipedia': info_wikipedia,
        'tweets': tweets
    })


if __name__ == '__main__':

    update_vulnerabilities_table()
    app.run(port=80, debug=True)

