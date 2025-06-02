from bokeh.plotting import figure
from bokeh.models import ColumnDataSource


def volunteer_status(df):
    counts = df['isVolunteer'].value_counts()
    source = ColumnDataSource(data=dict(
        volunteer_status=counts.index.map({True: 'Volunteer', False: 'Not Volunteer'}).tolist(),
        count=counts.values
    ))

    fig = figure(x_range=source.data['volunteer_status'], height=300, title="Volunteer Status",
                 toolbar_location=None, tools="")
    fig.vbar(x='volunteer_status', top='count', width=0.9, source=source)
    fig.y_range.start = 0
    return fig