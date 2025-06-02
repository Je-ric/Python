from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.transform import factor_cmap
from bokeh.palettes import Spectral5
import pandas as pd

def chart(df):
    bins = [17, 25, 35, 45, 55, 100]
    labels = ['18-25', '26-35', '36-45', '46-55', '56+']
    df['ageGroup'] = pd.cut(df['age'], bins=bins, labels=labels)

    age_group_counts = df['ageGroup'].value_counts().sort_index()
    age_source = ColumnDataSource(data=dict(ageGroup=age_group_counts.index.tolist(), count=age_group_counts.values))

    p = figure(x_range=age_group_counts.index.tolist(), height=350, 
               title="Age Group Distribution",
               toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    # Color bars by ageGroup using a palette
    mapper = factor_cmap('ageGroup', palette=Spectral5, factors=age_group_counts.index.tolist())
    
    p.vbar(x='ageGroup', top='count', width=0.9, source=age_source, color=mapper)

    p.y_range.start = 0
    p.xgrid.grid_line_color = None

    # Add hover tooltips
    hover = HoverTool(tooltips=[("Age Group", "@ageGroup"), ("Count", "@count")])
    p.add_tools(hover)

    return p
