from bokeh.plotting import figure
from bokeh.models import ColumnDataSource

def chart(df):
    hours_avg = df.groupby('programName')['hoursContribution'].mean().dropna().sort_values(ascending=False)
    hours_source = ColumnDataSource(data=dict(program=hours_avg.index.tolist(), avgHours=hours_avg.values))

    p = figure(x_range=hours_avg.index.tolist(), height=300, title="Average Hours Contributed per Program",
               toolbar_location=None, tools="")
    p.vbar(x='program', top='avgHours', width=0.9, source=hours_source)
    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    return p
