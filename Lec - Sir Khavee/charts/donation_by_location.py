from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.layouts import column
from math import pi
import pandas as pd

def donation_by_location(df):
    # Aggregate data
    grouped = df.groupby('location')['donation'].sum().sort_values(ascending=False)
    locations = grouped.index.tolist()
    donations = grouped.values
    
    source = ColumnDataSource(data=dict(locations=locations, donations=donations))

    # Create figure with line chart only
    fig = figure(x_range=locations, height=300, width=800, title="Total Donations by Location",
                 toolbar_location="above", tools="pan,box_zoom,reset,save")
    
    fig.line(x='locations', y='donations', source=source, line_width=3, color='navy', legend_label="Donations")
    fig.circle(x='locations', y='donations', source=source, size=8, color='navy')

    # Add hover tool
    hover = HoverTool(tooltips=[
        ("Location", "@locations"),
        ("Donation", "@donations{$0,0.00}")
    ], mode='vline')
    fig.add_tools(hover)

    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0
    fig.legend.location = "top_left"
    fig.xaxis.axis_label = "Location"
    fig.yaxis.axis_label = "Total Donations"

    return fig
