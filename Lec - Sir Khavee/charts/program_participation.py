from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool

def program_participation(df):
    counts = df['programName'].value_counts()
    source = ColumnDataSource(data=dict(program=counts.index.tolist(), count=counts.values))

    # Horizontal bar chart: y_range gets the categories, x is numerical
    fig = figure(y_range=counts.index.tolist(), height=400, title="Program Participation",
                 toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    bars = fig.hbar(y='program', right='count', height=0.7, source=source,
                    fill_color="teal", line_color="black", hover_fill_color="orange")

    # Add hover tooltips
    hover = HoverTool(tooltips=[("Program", "@program"), ("Count", "@count")], renderers=[bars])
    fig.add_tools(hover)

    fig.x_range.start = 0
    fig.ygrid.grid_line_color = None

    return fig
