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
print("-------------------------------------------------------")
print(" AGRUPACIONES POR PRIORIDAD")
print("-------------------------------------------------------")

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
print("Nº de vulnerabilidades detectadas en alertas P2: ", total_p2)
print("Nº de vulnerabilidades detectadas en alertas P3: ", total_p3)

print("-------------------------------------------------------")

# Nº VALORES AUSENTES

total_valores_null_p1 = 0
for columna in alerts_p1.columns:
    if alerts_p1[columna].eq("NULL").any():
        total_valores_null_p1 += alerts_p1[columna].eq("NULL").sum()

total_valores_null_p2 = 0
for columna in alerts_p2.columns:
    if alerts_p2[columna].eq("NULL").any():
        total_valores_null_p2 += alerts_p2[columna].eq("NULL").sum()

total_valores_null_p3 = 0
for columna in alerts_p3.columns:
    if alerts_p3[columna].eq("NULL").any():
        total_valores_null_p3 += alerts_p3[columna].eq("NULL").sum()

print("Nº valores ausentes: ", total_valores_null_p3+total_valores_null_p2+total_valores_null_p1)
print("Nº valores ausentes en P1: ", total_valores_null_p1)
print("Nº valores ausentes en P2: ", total_valores_null_p2)
print("Nº valores ausentes en P2: ", total_valores_null_p3)
print("-------------------------------------------------------")
"""
total_valores_null = 0
for valor in join_tables_df['localizacion']:
    if valor == "NULL":
        total_valores_null += 1

print(total_valores_null)
"""
# MODA

moda_p1 = alerts_p1['analisisVulnerabilidades']
frecuencia_p1 = moda_p1.value_counts()
mas_frecuente_p1 = frecuencia_p1.idxmax()
repeticiones_p1 = frecuencia_p1[mas_frecuente_p1]

moda_p2 = alerts_p2['analisisVulnerabilidades']
frecuencia_p2 = moda_p2.value_counts()
mas_frecuente_p2 = frecuencia_p2.idxmax()
repeticiones_p2 = frecuencia_p2[mas_frecuente_p2]

moda_p3 = alerts_p3['analisisVulnerabilidades']
frecuencia_p3 = moda_p3.value_counts()
mas_frecuente_p3 = frecuencia_p3.idxmax()
repeticiones_p3 = frecuencia_p3[mas_frecuente_p3]

print("La moda de las vulnerabilidades detectadas de P1: ", mas_frecuente_p1, "con ", repeticiones_p1, "repeticiones")
print("La moda de las vulnerabilidades detectadas de P1: ", mas_frecuente_p2, "con ", repeticiones_p2, "repeticiones")
print("La moda de las vulnerabilidades detectadas de P1: ", mas_frecuente_p3, "con ", repeticiones_p3, "repeticiones")
print("-------------------------------------------------------")

# MEDIANA

mediana_prioridad = join_tables_df.groupby('prioridad')['analisisVulnerabilidades'].median()
print("La mediana por prioridad es: ", mediana_prioridad)

print("-------------------------------------------------------")

# CUARTILES Q1 Y Q3

quartiles = alerts_p1['analisisVulnerabilidades'].quantile([0.25, 0.5, 0.75])
print("Cuartiles P1:")
print("Q1:", quartiles[0.25])
print("Q2 (Mediana):", quartiles[0.5])
print("Q3:", quartiles[0.75])

quartiles = alerts_p2['analisisVulnerabilidades'].quantile([0.25, 0.5, 0.75])
print("Cuartiles P2:")
print("Q1:", quartiles[0.25])
print("Q2 (Mediana):", quartiles[0.5])
print("Q3:", quartiles[0.75])

quartiles = alerts_p3['analisisVulnerabilidades'].quantile([0.25, 0.5, 0.75])
print("Cuartiles P3:")
print("Q1:", quartiles[0.25])
print("Q2 (Mediana):", quartiles[0.5])
print("Q3:", quartiles[0.75])


# VALORES MAX. Y MIN.

print(f"El nº minimo de vulnerabilidades detectadas de P1 son: {alerts_p1['analisisVulnerabilidades'].min()}")
print(f"El nº maximo de vulnerabilidades detectadas de P1 son: {alerts_p1['analisisVulnerabilidades'].max()}")
print(f"El nº minimo de vulnerabilidades detectadas de P2 son: {alerts_p2['analisisVulnerabilidades'].min()}")
print(f"El nº maximo de vulnerabilidades detectadas de P2 son: {alerts_p2['analisisVulnerabilidades'].max()}")
print(f"El nº minimo de vulnerabilidades detectadas de P3 son: {alerts_p3['analisisVulnerabilidades'].min()}")
print(f"El nº maximo de vulnerabilidades detectadas de P3 son: {alerts_p3['analisisVulnerabilidades'].max()}")

print("\n")

######################################
# POR FECHA: JULIO | AGOSTO
######################################
print("-------------------------------------------------------")
print(" AGRUPACIONES POR FECHA: JULIO Y AGOSTO")
print("-------------------------------------------------------")

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

print("-------------------------------------------------------")

# Nº VALORES AUSENTES

total_valores_null = 0
for columna in join_tables_df.columns:
    if join_tables_df[columna].eq("NULL").any():
        total_valores_null += join_tables_df[columna].eq("NULL").sum()

total_valores_null_julio = 0
for columna in julio_df.columns:
    if julio_df[columna].eq("NULL").any():
        total_valores_null_julio += julio_df[columna].eq("NULL").sum()

total_valores_null_agosto = 0
for columna in agosto_df.columns:
    if agosto_df[columna].eq("NULL").any():
        total_valores_null_agosto += agosto_df[columna].eq("NULL").sum()

print("Nº valores ausentes del mes de julio: ", total_valores_null_julio)
print("Nº valores ausentes del mes de agosto: ", total_valores_null_agosto)
print("-------------------------------------------------------")


# MODA

moda_julio = julio_df['analisisVulnerabilidades']
frecuencia_julio = moda_julio.value_counts()
mas_frecuente_julio = frecuencia_julio.idxmax()
repeticiones_julio = frecuencia_julio[mas_frecuente_julio]

moda_agosto = agosto_df['analisisVulnerabilidades']
frecuencia_agosto = moda_agosto.value_counts()
mas_frecuente_agosto = frecuencia_agosto.idxmax()
repeticiones_agosto = frecuencia_agosto[mas_frecuente_agosto]

print("La moda de las vulnerabilidades detectadas en julio es:", mas_frecuente_julio, "con ", repeticiones_julio, "repeticiones")
print("La moda de las vulnerabilidades detectadas en agosto es:", mas_frecuente_agosto, "con ", repeticiones_agosto, "repeticiones")
print("*Entendemos por repeticiones al numero de alertas que tienen 15 vulnerabilidades detectadas, y no al número total de vulnerabilidades.")
print("-------------------------------------------------------")

# MEDIANA

mediana_julio =join_tables_df.loc[join_tables_df['timestamp'].dt.month.isin([7]), 'analisisVulnerabilidades'].median()
mediana_agosto =join_tables_df.loc[join_tables_df['timestamp'].dt.month.isin([8]), 'analisisVulnerabilidades'].median()

print("La mediana agrupando por el mes de julio es: ", mediana_julio)
print("La mediana agrupando por el mes de agosto es: ", mediana_agosto)

print("-------------------------------------------------------")



# CUARTILES Q1 Y Q3


quartiles = julio_df['analisisVulnerabilidades'].quantile([0.25, 0.5, 0.75])
print("Cuartiles julio:")
print("Q1:", quartiles[0.25])
print("Q2 (Mediana):", quartiles[0.5])
print("Q3:", quartiles[0.75])

quartiles = agosto_df['analisisVulnerabilidades'].quantile([0.25, 0.5, 0.75])
print("Cuartiles agosto:")
print("Q1:", quartiles[0.25])
print("Q2 (Mediana):", quartiles[0.5])
print("Q3:", quartiles[0.75])

# VALORES MAX. Y MIN.

print(f"El nº minimo de vulnerabilidades detectadas en julio es:  {julio_df['analisisVulnerabilidades'].min()}")
print(f"El nº maximo de vulnerabilidades detectadas en julio es: {julio_df['analisisVulnerabilidades'].max()}")
print(f"El nº minimo de vulnerabilidades detectadas en agosto es: {agosto_df['analisisVulnerabilidades'].min()}")
print(f"El nº maximo de vulnerabilidades detectadas en agosto es: {agosto_df['analisisVulnerabilidades'].max()}")


conexion.close()