from bokeh.plotting import figure
from math import pi
# from bokeh.plotting import figure, show, output_file
# from bokeh.layouts import gridplot
# from bokeh.models import ColumnDataSource, HoverTool
# from bokeh.palettes import Category20c
# from bokeh.palettes import Category10
# from bokeh.transform import cumsum
import pandas as pd
# import numpy as np
# from math import pi


def rating_by_program(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    grouped = df.groupby('programName')['averageRating'].mean().sort_values(ascending=False).dropna()

    fig = figure(x_range=grouped.index.tolist(), height=300, title="Average Rating per Program",
                 toolbar_location=None, tools="")
    fig.vbar(x=grouped.index.tolist(), top=grouped.values, width=0.9)
    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0
    return fig