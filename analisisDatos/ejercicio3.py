import sqlite3
import pandas as pd
import numpy as np
import re
from numpy import nan

conexion = sqlite3.connect('alerts_database.db')
c = conexion.cursor()


join_tables_df = pd.read_sql_query('SELECT * FROM alerts JOIN devices ON (alerts.origen = devices.ip OR alerts.destino = devices.ip)', conexion)

######################################
# AGRUPACION POR PRIORIDAD DE ALERTA
######################################

alerts_p1 = join_tables_df.loc[join_tables_df['prioridad'] == 1]
alerts_p2 = join_tables_df.loc[join_tables_df['prioridad'] == 2]
alerts_p3 = join_tables_df.loc[join_tables_df['prioridad'] == 3]

# Nº OBSERVACIONES

print(f"Numero de alertas P1: {alerts_p1.__len__()}")
print(f"Numero de alertas P2: {alerts_p2.__len__()}")
print(f"Numero de alertas P3: {alerts_p3.__len__()}")

vuln_p1 = alerts_p1.loc[alerts_p1['analisisVulnerabilidades'] > 0]
total_p1 = vuln_p1['analisisVulnerabilidades'].sum()

vuln_p2 = alerts_p2.loc[alerts_p2['analisisVulnerabilidades'] > 0]
total_p2 = vuln_p2['analisisVulnerabilidades'].sum()

vuln_p3 = alerts_p3.loc[alerts_p3['analisisVulnerabilidades'] > 0]
total_p3 = vuln_p3['analisisVulnerabilidades'].sum()

print("Nº de vulnerabilidades detectadas en alertas P1: ", total_p1)
print("Nº de vulnerabilidades detectadas en alertas P1: ", total_p2)
print("Nº de vulnerabilidades detectadas en alertas P1: ", total_p3)

print("\n")

# Nº VALORES AUSENTES


print("Nº valores ausentes: ")
print("Nº valores ausentes en P1: ")
print("Nº valores ausentes en P2: ")
print("Nº valores ausentes en P2: ")

# MODA

# MEDIANA

# CUARTILES Q1 Y Q3


# VALORES MAX. Y MIN.



######################################
# POR FECHA: JULIO | AGOSTO
######################################

join_tables_df['timestamp'] = pd.to_datetime(join_tables_df['timestamp'], format = '%Y-%m-%d %H:%M:%S')
julio_df = join_tables_df[(join_tables_df['timestamp'].dt.month == 7)]
agosto_df = join_tables_df[(join_tables_df['timestamp'].dt.month == 8)]

# Nº OBSERVACIONES

print(f"Nº observaciones en julio: {julio_df.__len__()}")
print(f"Nº observaciones en agosto: {agosto_df.__len__()}")

vuln_julio = julio_df.loc[julio_df['analisisVulnerabilidades'] > 0]
total_julio = vuln_julio['analisisVulnerabilidades'].sum()

vuln_agosto = agosto_df.loc[agosto_df['analisisVulnerabilidades'] > 0]
total_agosto = vuln_agosto['analisisVulnerabilidades'].sum()

print("Nº vulnerabilidades detectadas en julio: ", total_julio)
print("Nº vulnerabilidades detectadas en agosto: ", total_agosto)

# Nº VALORES AUSENTES

print("Nº valores ausentes: ")
print("Nº valores ausentes del mes de julio: ")
print("Nº valores ausentes del mes de agosto: ")


# MODA

# MEDIANA

# CUARTILES Q1 Y Q3



# VALORES MAX. Y MIN.













conexion.close()