
import json
import matplotlib.pyplot as plt

with open("evaluation/summary.json", "r") as file:
    data = json.load(file)

names = ["FULL_FUSION"]
scores = []

for item in data["summaries"]:
    if item["scenario"] == "FULL_FUSION":
        scores.append(item["auc"])

for item in data["summaries"]:
    if item["scenario"].startswith("WITHOUT_"):
        names.append(item["scenario"].replace("WITHOUT_dom_", ""))
        scores.append(item["auc"])

plt.figure(figsize=(12, 6))
bars = plt.bar(names, scores)

plt.title("Effect of Removing DOM Features")
plt.xlabel("Configuration")
plt.ylabel("ROC-AUC")
plt.ylim(0, 1)
plt.xticks(rotation=35, ha="right")

for bar, score in zip(bars, scores):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 0.01,
        f"{score:.4f}",
        ha="center"
    )

plt.tight_layout()
plt.savefig("evaluation/dom_ablation.png", dpi=300)
plt.show()
