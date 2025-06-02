from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
import pandas as pd
from bokeh.palettes import Category20  # palette with 20 distinct colors

def chart(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    rating_by_role = df.groupby('userRole')['averageRating'].mean().dropna().sort_values(ascending=True)

    roles = rating_by_role.index.tolist()
    ratings = rating_by_role.values

    # Pick a color for each role, cycling if more roles than colors
    palette = Category20[20]  # max 20 colors
    colors = [palette[i % len(palette)] for i in range(len(roles))]

    source = ColumnDataSource(data=dict(
        role=roles,
        avgRating=ratings,
        color=colors
    ))

    p = figure(y_range=roles, height=400, width=700,
               title="Average Rating by User Role",
               toolbar_location="above",
               tools="pan,box_zoom,reset,save")

    p.hbar(y='role', right='avgRating', height=0.6, source=source, color='color')

    hover = HoverTool(tooltips=[
        ("Role", "@role"),
        ("Average Rating", "@avgRating{0.00}")
    ])
    p.add_tools(hover)

    p.x_range.start = 0
    p.ygrid.grid_line_color = None
    p.xaxis.axis_label = "Average Rating"
    p.yaxis.axis_label = "User Role"

    return p
