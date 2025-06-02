from bokeh.plotting import figure
from bokeh.models import ColumnDataSource, HoverTool, LinearColorMapper, ColorBar
from bokeh.transform import transform
from bokeh.palettes import Blues9

def chart(df):
    skill_counts = df['skill'].value_counts().sort_values(ascending=False)
    skills = skill_counts.index.tolist()
    counts = skill_counts.values

    source = ColumnDataSource(data=dict(
        skill=skills,
        count=counts,
        x=[1]*len(skills),
        y=skills
    ))

    mapper = LinearColorMapper(palette=Blues9[::-1], low=min(counts), high=max(counts))

    p = figure(y_range=skills, x_range=(0, 2), height=400, width=600,
               title="Skill Distribution (Heatmap Style)",
               toolbar_location="above", tools="pan,box_zoom,reset,save")

    p.rect(x='x', y='y', width=1.5, height=0.8, source=source,
           fill_color=transform('count', mapper),
           line_color=None)

    hover = HoverTool(tooltips=[
        ("Skill", "@skill"),
        ("Count", "@count")
    ])
    p.add_tools(hover)

    p.xaxis.visible = False
    p.ygrid.grid_line_color = None
    p.yaxis.axis_label = "Skill"

    color_bar = ColorBar(color_mapper=mapper, location=(0,0), title="Count")
    p.add_layout(color_bar, 'right')

    # Set background color here
    p.background_fill_color = "#f0f0f0"  # light gray background

    return p
