import pandas as pd

def load_data(filepath="youmanitarian_user_data.csv"):
    df = pd.read_csv(filepath)
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    return df
