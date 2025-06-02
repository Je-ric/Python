from bokeh.plotting import figure
import numpy as np
# from bokeh.plotting import figure, show, output_file
# from bokeh.layouts import gridplot
# from bokeh.models import ColumnDataSource, HoverTool
# from bokeh.palettes import Category20c
# from bokeh.palettes import Category10
# from bokeh.transform import cumsum
import pandas as pd
# import numpy as np
# from math import pi

def rating_distribution(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    hist, edges = np.histogram(df['averageRating'].dropna(), bins=5, range=[1, 5])

    fig = figure(title='Rating Distribution', height=300)
    fig.quad(top=hist, bottom=0, left=edges[:-1], right=edges[1:], fill_color="navy", line_color="white")
    return fig
