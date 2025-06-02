from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
import pandas as pd

def chart(df):
    df['dateJoined'] = pd.to_datetime(df['dateJoined'], errors='coerce')

    df_members = df[df['isMember'] == True]
    df_members = df_members.dropna(subset=['dateJoined'])
    df_members['monthYear'] = df_members['dateJoined'].dt.to_period('M').astype(str)

    monthly_new_members = df_members.groupby('monthYear').size().sort_index()
    monthly_source = ColumnDataSource(data=dict(month=monthly_new_members.index.tolist(), count=monthly_new_members.values))

    p = figure(x_range=monthly_new_members.index.tolist(), height=300, width=900,
               title="Monthly New Membership Trends", toolbar_location=None, tools="")
    p.line(x='month', y='count', line_width=2, source=monthly_source)
    p.circle(x='month', y='count', size=5, source=monthly_source)
    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    return p
