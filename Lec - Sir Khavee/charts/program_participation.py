from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
from math import pi


def program_participation(df):
    counts = df['programName'].value_counts()
    source = ColumnDataSource(data=dict(program=counts.index.tolist(), count=counts.values))

    fig = figure(x_range=counts.index.tolist(), height=300, title="Program Participation",
                 toolbar_location=None, tools="")
    fig.vbar(x='program', top='count', width=0.9, source=source)
    fig.xaxis.major_label_orientation = pi / 4
    fig.y_range.start = 0
    return fig