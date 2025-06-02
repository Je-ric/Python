from bokeh.plotting import figure
from bokeh.models import Select, ColumnDataSource
from bokeh.layouts import column
from math import pi
import pandas as pd

def donation_by_location(df):
    # Aggregate data
    grouped = df.groupby('location')['donation'].sum().sort_values(ascending=False)
    locations = grouped.index.tolist()
    donations = grouped.values
    
    source = ColumnDataSource(data=dict(locations=locations, donations=donations))

    # Initial figure as bar chart
    fig = figure(x_range=locations, height=300, title="Total Donations by Location",
                 toolbar_location=None, tools="")
    bars = fig.vbar(x='locations', top='donations', width=0.9, source=source)
    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0
    
    # Dropdown to select chart type
    select = Select(title="Chart Type:", value="Bar", options=["Bar", "Line"])

    def update_chart(attr, old, new):
        chart_type = select.value
        
        fig.renderers = []  # Clear existing glyphs
        fig.x_range.factors = locations  # Reset x-axis factors
        
        if chart_type == "Bar":
            fig.vbar(x='locations', top='donations', width=0.9, source=source)
        elif chart_type == "Line":
            fig.line(x='locations', y='donations', source=source, line_width=2)
            fig.circle(x='locations', y='donations', source=source, size=8)
        
        fig.xaxis.major_label_orientation = pi / 4
        fig.y_range.start = 0

    select.on_change('value', update_chart)
    
    layout = column(select, fig)
    return layout
