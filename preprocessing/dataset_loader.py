from collections.abc import Sequence
from pathlib import Path

import pandas as pd
from PIL import Image
from torch.utils.data import DataLoader, Dataset

from preprocessing.transforms import get_eval_transforms, get_train_transforms


class MalwareDataset(Dataset):
    def __init__(
        self,
        csv_path: str | Path,
        class_names: Sequence[str] | None = None,
        transform=None,
    ) -> None:
        self.csv_path = Path(csv_path)
        self.dataframe = pd.read_csv(self.csv_path)

        required_columns = {"filepath", "label"}
        missing_columns = required_columns.difference(self.dataframe.columns)
        if missing_columns:
            raise ValueError(
                f"Missing required columns in {self.csv_path}: {sorted(missing_columns)}"
            )

        self.class_names = list(class_names) if class_names is not None else sorted(
            self.dataframe["label"].unique().tolist()
        )
        self.class_to_idx = {
            class_name: index for index, class_name in enumerate(self.class_names)
        }
        self.transform = transform

    def __len__(self) -> int:
        return len(self.dataframe)

    def __getitem__(self, index: int):
        row = self.dataframe.iloc[index]
        image_path = Path(row["filepath"])
        label_name = row["label"]

        if label_name not in self.class_to_idx:
            raise KeyError(f"Unknown label {label_name} in {self.csv_path}")

        with Image.open(image_path) as image:
            image = image.convert("RGB")
            transformed_image = self.transform(image) if self.transform else image

        label_index = self.class_to_idx[label_name]
        return transformed_image, label_index


def infer_class_names(csv_paths: Sequence[str | Path]) -> list[str]:
    labels: set[str] = set()
    for csv_path in csv_paths:
        dataframe = pd.read_csv(csv_path)
        labels.update(dataframe["label"].unique().tolist())

    if not labels:
        raise RuntimeError("No labels found across split files.")

    return sorted(labels)


def create_dataloaders(
    train_csv: str | Path,
    val_csv: str | Path,
    test_csv: str | Path,
    batch_size: int = 32,
    num_workers: int = 0,
    image_size: int = 224,
) -> tuple[dict[str, DataLoader], list[str]]:
    class_names = infer_class_names([train_csv, val_csv, test_csv])

    datasets = {
        "train": MalwareDataset(
            csv_path=train_csv,
            class_names=class_names,
            transform=get_train_transforms(image_size=image_size),
        ),
        "val": MalwareDataset(
            csv_path=val_csv,
            class_names=class_names,
            transform=get_eval_transforms(image_size=image_size),
        ),
        "test": MalwareDataset(
            csv_path=test_csv,
            class_names=class_names,
            transform=get_eval_transforms(image_size=image_size),
        ),
    }

    dataloaders = {
        split_name: DataLoader(
            dataset,
            batch_size=batch_size,
            shuffle=split_name == "train",
            num_workers=num_workers,
            pin_memory=False,
        )
        for split_name, dataset in datasets.items()
    }

    return dataloaders, class_names
