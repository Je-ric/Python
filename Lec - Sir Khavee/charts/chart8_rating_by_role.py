from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
import pandas as pd

def chart(df):
    df['averageRating'] = pd.to_numeric(df['averageRating'], errors='coerce')
    rating_by_role = df.groupby('userRole')['averageRating'].mean().dropna().sort_values(ascending=False)
    rating_role_source = ColumnDataSource(data=dict(role=rating_by_role.index.tolist(), avgRating=rating_by_role.values))

    p = figure(x_range=rating_by_role.index.tolist(), height=300, title="Average Rating by User Role",
               toolbar_location=None, tools="")
    p.vbar(x='role', top='avgRating', width=0.9, source=rating_role_source)
    p.xaxis.major_label_orientation = 3.14 / 4
    p.y_range.start = 0
    return p
