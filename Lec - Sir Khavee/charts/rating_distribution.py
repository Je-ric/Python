from bokeh.plotting import figure
import numpy as np
import pandas as pd
def rating_distribution(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    hist, edges = np.histogram(df['averageRating'].dropna(), bins=5, range=[1, 5])

    fig = figure(title='Rating Distribution', height=300)
    fig.quad(top=hist, bottom=0, left=edges[:-1], right=edges[1:], fill_color="navy", line_color="white")
    return fig
