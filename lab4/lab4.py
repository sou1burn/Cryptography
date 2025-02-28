import numpy as np
import time
import csv
import pandas as pd
import matplotlib.pyplot as plt


def plot_collision_power(csv_file):

    bitCounts = []
    powers = []

    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['bitCount'].strip() and row['Power'].strip():
                bitCounts.append(int(row['bitCount']))
                powers.append(int(row['Power']))

    plt.figure(figsize=(10, 6))
    plt.bar(bitCounts, powers, color='blue', alpha=0.7)
    plt.title('Зависимость среднего значения сложности коллизии от количества взятых бит')
    plt.xlabel('Количество бит')
    plt.ylabel('Сложность коллизии (шагов)')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.show()


plot_collision_power("experiment.csv")