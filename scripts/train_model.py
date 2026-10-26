"""Train the classifier and print evaluation. Run from the project root:  python -m scripts.train_model"""
import json
from app.detection import ml_classifier

if __name__ == "__main__":
    print(json.dumps(ml_classifier.train(), indent=2))
