from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool
import pandas as pd

def chart(df):
    df['dateJoined'] = pd.to_datetime(df['dateJoined'], errors='coerce')

    df_members = df[df['isMember'] == True].dropna(subset=['dateJoined'])
    df_members['monthYear'] = df_members['dateJoined'].dt.to_period('M').astype(str)

    monthly_new_members = df_members.groupby('monthYear').size().sort_index()
    monthly_source = ColumnDataSource(data=dict(
        month=monthly_new_members.index.tolist(),
        count=monthly_new_members.values
    ))

    p = figure(x_range=monthly_new_members.index.tolist(), height=300, width=900,
               title="Monthly New Membership Trends", 
               toolbar_location="above", tools="pan,box_zoom,reset,save")

    p.line(x='month', y='count', line_width=2, source=monthly_source, color="navy", legend_label="New Members")
    p.circle(x='month', y='count', size=6, source=monthly_source, color="orange", legend_label="Monthly Count")

    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    p.xaxis.axis_label = "Month"
    p.yaxis.axis_label = "Number of New Members"

    # Add interactivity
    hover = HoverTool(tooltips=[
        ("Month", "@month"),
        ("New Members", "@count")
    ])
    p.add_tools(hover)

    p.legend.location = "top_left"
    p.legend.click_policy = "hide"

    return p
