from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool

def gender_distribution(df):
    gender_counts = df['gender'].value_counts()
    source = ColumnDataSource(data=dict(gender=gender_counts.index.tolist(), count=gender_counts.values))

    fig = figure(x_range=gender_counts.index.tolist(), height=300, title="Gender Distribution",
                 toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    # Add vbars with source
    bars = fig.vbar(x='gender', top='count', width=0.9, source=source, 
                    fill_color="steelblue", line_color="black", hover_fill_color="orange")

    # Add hover tool
    hover = HoverTool(tooltips=[("Gender", "@gender"), ("Count", "@count")], renderers=[bars])
    fig.add_tools(hover)

    fig.xgrid.grid_line_color = None
    fig.y_range.start = 0

    return fig
