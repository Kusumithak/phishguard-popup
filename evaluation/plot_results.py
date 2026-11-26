
import json
import matplotlib.pyplot as plt

with open("evaluation/summary.json", "r") as file:
    data = json.load(file)

names = []
auc_scores = []

for item in data["summaries"]:
    if item["scenario"] in [
        "ML_ONLY",
        "URL_RULES_ONLY",
        "DOM_ONLY",
        "URL_ONLY",
        "FULL_FUSION",
        "REDUCED_DOM_FUSION"
    ]:
        names.append(item["scenario"])
        auc_scores.append(item["auc"])

plt.figure(figsize=(10, 5))
bars = plt.bar(names, auc_scores)

plt.title("PhishGuard - AUC Comparison")
plt.xlabel("Detection Configuration")
plt.ylabel("ROC-AUC")
plt.ylim(0, 1)
plt.xticks(rotation=20, ha="right")

for bar, score in zip(bars, auc_scores):
    plt.text(
        bar.get_x() + bar.get_width() / 2,
        bar.get_height() + 0.01,
        f"{score:.4f}",
        ha="center"
    )

plt.tight_layout()
plt.savefig("evaluation/auc_comparison.png", dpi=300)
plt.show()
