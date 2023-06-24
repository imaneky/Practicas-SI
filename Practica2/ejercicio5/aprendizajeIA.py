import json
import matplotlib.pyplot as plt
import numpy as np
from sklearn import linear_model, tree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import mean_squared_error, accuracy_score
from sklearn.tree import export_graphviz
import graphviz


def load_data(file_path):
    with open(file_path) as file:
        data = json.load(file)
    return data

def preprocess_data(data):
    data_x = []
    data_y = []
    for device in data:
        data_y.append([device["peligroso"]])
        data_x.append([device["servicios_inseguros"], device["servicios"]])
    return data_x, data_y

def train_linear_regression(data_x_train, data_y_train):
    regr = linear_model.LinearRegression()
    regr.fit(data_x_train, data_y_train)
    return regr

def predict_linear_regression(model, data_x_test):
    data_y_pred = model.predict(np.array(data_x_test))
    data_y_pred = np.where(data_y_pred < 0.5, 0, 1)
    return data_y_pred

def train_decision_tree(data_x_train, data_y_train):
    clf = tree.DecisionTreeClassifier()
    clf.fit(data_x_train, data_y_train)
    return clf

def train_random_forest(data_x_train, data_y_train):
    clf = RandomForestClassifier(max_depth=2, random_state=0, n_estimators=10)
    clf.fit(data_x_train, np.ravel(data_y_train))
    return clf

def plot_regression_results(x, y_test, y_pred, model):
    x_real = []
    for i in x:
        if i[1] == 0:
            i[1] = 0.01
        x_real.append(i[0] / i[1])
    x = x_real

    m = model.coef_
    b = model.intercept_

    plt.scatter(np.array(x), np.array(y_test), color="black")
    plt.plot(np.array(x), (m[0][0] * np.array(x)) + b, color="blue")
    plt.show()

def export_decision_tree_graph(clf, output_file):
    dot_data = tree.export_graphviz(clf, out_file=None, filled=True, rounded=True, special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.render(output_file, view=True)

def export_random_forest_trees(clf):
    for i, estimator in enumerate(clf.estimators_):
        export_decision_tree_graph(estimator, f'RandomForest_{i}')

def main():
    with open('C:/Users/Georgia/Desktop/sistemas informacion/Practicas-SI-main/Practica2/ejercicio5/devices_IA_clases.json') as file:
        data_devices_train = json.load(file)

    with open('C:/Users/Georgia/Desktop/sistemas informacion/Practicas-SI-main/Practica2/ejercicio5/devices_IA_predecir_v2.json') as file:
        data_devices_test = json.load(file)

    data_x_train, data_y_train = preprocess_data(data_devices_train)
    data_x_test, data_y_test = preprocess_data(data_devices_test)

    regr = train_linear_regression(data_x_train[:-20], data_y_train[:-20])
    data_y_pred = predict_linear_regression(regr, data_x_test)

    mse = mean_squared_error(data_y_test, data_y_pred)
    accuracy_linear_regression = accuracy_score(data_y_test, data_y_pred)
    print(f"Mean Squared Error (Linear Regression): {mse}")
    print(f"Accuracy (Linear Regression): {accuracy_linear_regression}")

    num_peligrosos_pred = sum(data_y_pred)
    num_no_peligrosos_pred = len(data_y_pred) - num_peligrosos_pred

    print(f"Número de dispositivos peligrosos según linear regression: {num_peligrosos_pred}")
    print(f"Número de dispositivos no peligrosos según linear regression: {num_no_peligrosos_pred}")

    clf = train_decision_tree(data_x_train[:-20], data_y_train[:-20])
    data_y_pred = clf.predict(data_x_test)

    accuracy_decision_tree = accuracy_score(data_y_test, data_y_pred)
    print(f"Accuracy (Decision Tree): {accuracy_decision_tree}")

    export_decision_tree_graph(clf, 'DecisionTree')  # Exportar el árbol de decisión en formato DOT y guardar en archivo
    # Mostrar el gráfico del árbol de decisión
    dot_data = tree.export_graphviz(clf, out_file=None, filled=True, rounded=True, special_characters=True)
    graph = graphviz.Source(dot_data)
    graph.view()

    num_peligrosos_decision_tree = sum(data_y_pred)
    num_no_peligrosos_decision_tree = len(data_y_pred) - num_peligrosos_decision_tree

    print(f"Número de dispositivos peligrosos según el árbol de decisión: {num_peligrosos_decision_tree}")
    print(f"Número de dispositivos no peligrosos según el árbol de decisión: {num_no_peligrosos_decision_tree}")

    clf = train_random_forest(data_x_train[:-20], data_y_train[:-20])
    data_y_pred = clf.predict(data_x_test)

    accuracy_random_forest = accuracy_score(data_y_test, data_y_pred)
    print(f"Accuracy (Random Forest): {accuracy_random_forest}")

    num_peligrosos_random_forest = sum(data_y_pred)
    num_no_peligrosos_random_forest = len(data_y_pred) - num_peligrosos_random_forest

    print(f"Número de dispositivos peligrosos según Random Forest: {num_peligrosos_random_forest}")
    print(f"Número de dispositivos no peligrosos según Random Forest: {num_no_peligrosos_random_forest}")

    plot_regression_results(data_x_test, data_y_test, data_y_pred, regr)
    export_decision_tree_graph(clf.estimators_[0], 'DecisionTree')
    export_random_forest_trees(clf)

if __name__ == "__main__":
    main()
