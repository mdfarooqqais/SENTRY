import pandas as pd
import glob
import os

DATA_DIR = "data/CICIDS2017"
OUTPUT_FILE = "data/processed_cicids2017.csv"

CHUNK_SIZE = 50000

FEATURES = [
    "Destination Port",
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Bwd IAT Total",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "AveragePacket Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward"
]

files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

print(f"Found {len(files)} CSV files")

os.makedirs("data", exist_ok=True)

if os.path.exists(OUTPUT_FILE):
    os.remove(OUTPUT_FILE)

first_write = True
total_rows = 0

for file in files:

    print(f"\nProcessing: {os.path.basename(file)}")

    for chunk in pd.read_csv(
    file,
    chunksize=CHUNK_SIZE,
    low_memory=False,
    encoding="latin1"
    ):

        chunk.columns = chunk.columns.str.strip()

        available_features = [
            column for column in FEATURES
            if column in chunk.columns
        ]

        selected = chunk[available_features + ["Label"]].copy()

        selected["Label"] = (
            selected["Label"]
            .astype(str)
            .str.strip()
        )

        for column in available_features:
            selected[column] = pd.to_numeric(
                selected[column],
                errors="coerce"
            )

        selected = selected.replace(
            [float("inf"), float("-inf")],
            float("nan")
        )

        selected = selected.dropna()

        selected = selected[
            selected["Label"].str.len() > 0
        ]

        selected.to_csv(
            OUTPUT_FILE,
            mode="w" if first_write else "a",
            header=first_write,
            index=False
        )

        first_write = False

        total_rows += len(selected)

        print(
            f"Processed rows: {total_rows}",
            end="\r"
        )

print("\n\nPreprocessing completed.")

print(f"Output file: {OUTPUT_FILE}")
print(f"Total rows: {total_rows}")

print("\nAttack distribution:")

df = pd.read_csv(
    OUTPUT_FILE,
    usecols=["Label"]
)

print(df["Label"].value_counts())