from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
from bokeh.transform import factor_cmap
from bokeh.palettes import Category20

def program_participation(df):
    counts = df['programName'].value_counts()
    programs = counts.index.tolist()
    source = ColumnDataSource(data=dict(program=programs, count=counts.values))

    # Use a palette matching number of programs (max 20 colors)
    palette = Category20[max(3, min(20, len(programs)))]

    fig = figure(y_range=programs, height=500, width=750, title="Program Participation",
                 toolbar_location="above", tools="pan,wheel_zoom,box_zoom,reset")

    bars = fig.hbar(y='program', right='count', height=0.7, source=source,
                    fill_color=factor_cmap('program', palette=palette, factors=programs),
                    line_color="black", hover_fill_color="orange")

    hover = HoverTool(tooltips=[("Program", "@program"), ("Count", "@count")], renderers=[bars])
    fig.add_tools(hover)

    fig.x_range.start = 0
    fig.ygrid.grid_line_color = None

    return fig
