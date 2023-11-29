# Copyright (c) 2023 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import csv
import matplotlib.pyplot as plt


def extract_data(filename):
    with open(filename, "r") as csvfile:
        data = list(csv.reader(csvfile, delimiter=","))
    x = [float(row[0]) for row in data[1:]]
    y_data = [[float(row[i]) for row in data[1:]] for i in range(1, len(data[0]))]
    return x, y_data, data[0][1:]


def plot_data(ax, x, y_data_simpl, y_data_true, labels):
    for i, y in enumerate(y_data_simpl):
        ax.plot(x, y)

    ax.set_prop_cycle(None)

    for i, y in enumerate(y_data_true):
        ax.plot(x, y, "--")

    ax.set_xlabel("Time (ms)")
    ax.legend(labels)


file_pairs = [
    ("results_bw_true.csv", "results_bw_simpl.csv"),
    ("results_ltc_true.csv", "results_ltc_simpl.csv"),
    ("results_jt_true.csv", "results_jt_simpl.csv"),
]

fig, axes = plt.subplots(nrows=len(file_pairs), ncols=1, figsize=(8, 12))

for i, (true_file, simpl_file) in enumerate(file_pairs):
    x, y_data_true, _ = extract_data(true_file)
    x, y_data_simpl, labels = extract_data(simpl_file)

    plot_data(axes[i], x, y_data_simpl, y_data_true, labels)

axes[0].set_ylabel("Bandwidth (bytes)")
axes[1].set_ylabel("Latency (ns)")
axes[2].set_ylabel("Jitter (ns)")

plt.tight_layout()
plt.show()
