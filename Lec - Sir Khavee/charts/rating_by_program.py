from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.palettes import Category20
import pandas as pd

def rating_by_program(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    grouped = df.groupby('programName')['averageRating'].mean().sort_values(ascending=True).dropna()

    programs = grouped.index.tolist()
    ratings = grouped.values

    # Pick colors cycling through Category20 palette
    palette = Category20[20]
    colors = [palette[i % 20] for i in range(len(programs))]

    source = ColumnDataSource(data=dict(
        programs=programs,
        ratings=ratings,
        colors=colors
    ))

    fig = figure(y_range=programs, height=400, width=700,
                 title="Average Rating per Program", toolbar_location="above",
                 tools="pan,box_zoom,reset,save")

    fig.hbar(y='programs', right='ratings', height=0.5, source=source, color='colors')

    fig.add_tools(HoverTool(
        tooltips=[("Program", "@programs"), ("Average Rating", "@ratings{0.00}")],
        mode='mouse'
    ))

    fig.x_range.start = 0
    fig.ygrid.grid_line_color = None
    fig.xaxis.axis_label = "Average Rating"
    fig.yaxis.axis_label = "Program Name"

    return fig
