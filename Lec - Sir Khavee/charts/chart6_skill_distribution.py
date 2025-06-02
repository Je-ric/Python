from bokeh.plotting import figure
from bokeh.models import ColumnDataSource

def chart(df):
    skill_counts = df['skill'].value_counts()
    skill_source = ColumnDataSource(data=dict(skill=skill_counts.index.tolist(), count=skill_counts.values))

    p = figure(y_range=skill_counts.index.tolist(), height=300, title="Skill Distribution",
               toolbar_location=None, tools="")
    p.hbar(y='skill', right='count', height=0.7, source=skill_source)
    p.x_range.start = 0
    return p
