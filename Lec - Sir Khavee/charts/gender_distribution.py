from bokeh.plotting import figure
from bokeh.models import ColumnDataSource

def gender_distribution(df):
    gender_counts = df['gender'].value_counts()
    source = ColumnDataSource(data=dict(gender=gender_counts.index.tolist(), count=gender_counts.values))

    fig = figure(x_range=gender_counts.index.tolist(), height=300, title="Gender Distribution",
                 toolbar_location=None, tools="")
    fig.vbar(x='gender', top='count', width=0.9, source=source)
    fig.xgrid.grid_line_color = None
    fig.y_range.start = 0
    return fig
