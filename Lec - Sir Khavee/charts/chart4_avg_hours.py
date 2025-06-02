from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
import pandas as pd

def chart(df):
    hours_avg = df.groupby('programName')['hoursContribution'].mean().dropna().sort_values(ascending=False)
    programs = hours_avg.index.tolist()
    avg_hours = hours_avg.values

    source = ColumnDataSource(data=dict(
        program=programs,
        avgHours=avg_hours,
        index=list(range(len(programs)))
    ))

    p = figure(y_range=programs, height=400, width=600, title="Average Hours Contributed per Program",
               toolbar_location="above", tools="pan,box_zoom,reset,save")

    # Add stems (segments)
    p.segment(x0=0, y0='program', x1='avgHours', y1='program', source=source, line_width=2, color="gray")

    # Add circles
    p.circle(x='avgHours', y='program', size=10, source=source, color="green", legend_label="Average Hours")

    # Tooltip
    hover = HoverTool(tooltips=[
        ("Program", "@program"),
        ("Avg Hours", "@avgHours{0.0}")
    ])
    p.add_tools(hover)

    p.x_range.start = 0
    p.ygrid.grid_line_color = None
    p.xaxis.axis_label = "Average Hours"
    p.yaxis.axis_label = "Program"

    return p
