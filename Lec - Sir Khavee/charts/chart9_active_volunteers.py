from bokeh.plotting import figure
from bokeh.models import ColumnDataSource

def chart(df):
    active_volunteers = df[(df['status'] == 'active') & (df['isVolunteer'] == True)]
    active_vol_counts = active_volunteers['programName'].value_counts()
    active_vol_source = ColumnDataSource(data=dict(program=active_vol_counts.index.tolist(), count=active_vol_counts.values))

    p = figure(x_range=active_vol_counts.index.tolist(), height=300, title="Active Volunteers by Program",
               toolbar_location=None, tools="")
    p.vbar(x='program', top='count', width=0.9, source=active_vol_source)
    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    return p
