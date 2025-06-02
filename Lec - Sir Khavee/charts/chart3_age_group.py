from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
import pandas as pd

def chart(df):
    bins = [17, 25, 35, 45, 55, 100]
    labels = ['18-25', '26-35', '36-45', '46-55', '56+']
    df['ageGroup'] = pd.cut(df['age'], bins=bins, labels=labels)

    age_group_counts = df['ageGroup'].value_counts().sort_index()
    age_source = ColumnDataSource(data=dict(ageGroup=age_group_counts.index.tolist(), count=age_group_counts.values))

    p = figure(x_range=age_group_counts.index.tolist(), height=300, title="Age Group Distribution",
               toolbar_location=None, tools="")
    p.vbar(x='ageGroup', top='count', width=0.9, source=age_source)
    p.y_range.start = 0
    return p
