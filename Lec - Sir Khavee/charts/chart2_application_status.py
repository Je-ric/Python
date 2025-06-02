from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
from math import pi

def chart(df):
    app_status_counts = df['volunteerApplicationStatus'].fillna('No Application').value_counts()
    app_status_source = ColumnDataSource(data=dict(
        status=app_status_counts.index.tolist(),
        count=app_status_counts.values
    ))

    p = figure(x_range=app_status_counts.index.tolist(), height=300, title="Volunteer Application Status Distribution",
               toolbar_location=None, tools="")
    p.vbar(x='status', top='count', width=0.9, source=app_status_source)
    p.xaxis.major_label_orientation = pi / 4
    p.y_range.start = 0
    return p
