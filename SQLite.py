import sqlite3
from datetime import datetime, date

import pandas as pd
import numpy as np

import time


if __name__ == '__main__':

    alerts_df = pd.read_csv("C:/Users/imane/OneDrive - Universidad Rey Juan Carlos/CURSO 22-23/SISTEMAS DE INFORMACIÓN/PRACTICA 1/Practica1_Codigo/alerts.csv")
    print(alerts_df.dtypes)

    #Obtener una columna
    #print(alerts_df['prioridad'])

    ##################################### EJERCICIO 3 #######################################
    ##Hay que calcular las estadisticas de las vulnerabilidades detectadas de prioridad 1, 2 o 3, y las detectadas
    #en julio o agosto

    #POR PRIORIDAD DE ALERTA
    #Graves
    #graves_df = alerts_df[alerts_df['prioridad'] == 3]
    graves_df = alerts_df.query('prioridad == 3')
    #print(graves_df.count())
    #Medias
    medias_df = alerts_df.query('prioridad == 2')
    #print((medias_df.count()))
    #Bajas (Tabla solo con ips origen y destino para parear con devices.json)
    bajas_df = alerts_df.query('prioridad == 1')[['origen','destino']]
    #print(bajas_df)

    #POR FECHA
    #Julio
    #julio_df = pd.to_datetime(alerts_df['timestamp'], unit='ns').dt.total_seconds().astype(int)
    #julio_df = pd.talerts_df['timestamp']
    print(alerts_df)
    #Grouped by
    #alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
    ##[alerts_df['timestamp'].dt.month == 07]

    print(alerts_df.dtypes)

    dates = pd.date_range(start='2022-07-03 00:19:55', end='2022-09-05 05:50:56', freq='1 day')
    grouped_df = pd.DataFrame({'timestamp':dates, 'value':np.random.uniform(-1,0,len(dates))})
    grouped_df.set_index('timestamp', inplace=True)
    alerts_df[alerts_df.index]
    input_date = datetime(year='2022', month='07', day='03')



    #print(julio_df)
    #alerts_df['timestamp'] = alerts_df.astype().to_timestamp()






    #Agosto

    #########################################################################################

    #grupo_prioridad = alerts_df.groupby(['prioridad'])[[]]
    #devices_df = pd.read_json("C:/Users/imane/OneDrive - Universidad Rey Juan Carlos/CURSO 22-23/SISTEMAS DE INFORMACIÓN/PRACTICA 1/datos_22_23/devices.json")
    #print(devices_df.columns)

    con = sqlite3.connect('alertas.db')


    def sql_create_table(con):
        cursorObj = con.cursor()
        alerts_df.e
        cursorObj.execute("CREATE TABLE IF NOT EXISTS alerts (time_stamp, sid, msg, clasificacion, prioridad, origen, destino, puerto)")
        cursorObj.execute("INSERT INTO alerts VALUES('al')")





